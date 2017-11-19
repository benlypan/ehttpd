#ifndef _EHTTPD_HPP
#define _EHTTPD_HPP

#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <algorithm>
#include <map>
#include <sstream>

#define ASIO_STANDALONE
#include <asio.hpp>

// utils
namespace ehttpd {
    namespace utils {
        struct string {
            static std::string to_lower(const std::string& input) {
                std::string output;
                std::transform(input.begin(), input.end(), std::back_inserter(output), std::tolower);
                return output;
            }

            static std::string to_lower(std::string&& input) {
                std::transform(input.begin(), input.end(), input.begin(), std::tolower);
                return std::move(input);
            }
        };
    }
}

// exceptions
namespace ehttpd {
    class ehttpd_exception : public std::exception {
    public:
        ehttpd_exception(const std::string& message) : _message(message) {}
        ehttpd_exception(std::string&& message) : _message(std::move(message)) {}

        virtual char const* what() const {
            return _message.c_str();
        }
    protected:
        std::string _message;
    };

    class ehttpd_bad_config_exception : public ehttpd_exception {
    public:
        ehttpd_bad_config_exception(const std::string& field, const std::string& value, const std::string& expect)
            : ehttpd_exception(format_message(field, value, expect)) {
        }

    private:
        std::string format_message(const std::string& field, const std::string& value, const std::string& expect) {
            std::string message;
            message.append("bad config value for ");
            message.append(field);
            message.append(", got: ");
            message.append(value);
            message.append(", expect: ");
            message.append(expect);
            return message;
        }
    };
}

// http status line
namespace ehttpd {
    enum class status_code {
        bad = 0,

        ok = 200,
        bad_request = 400,
        not_found = 404,
        request_entity_too_large = 413,
        internel_server_error = 500,
    };

    static inline const char* reason_phrase(status_code code) {
        switch (code) {
        case status_code::ok:
            return "OK";
        case status_code::bad_request:
            return "Bad Request";
        case status_code::not_found:
            return "Not Found";
        case status_code::request_entity_too_large:
            return "Request Entity Too Large";
        case status_code::internel_server_error:
            return "Internal Server Error";
        default:
            return "";
        }
    }
}

namespace ehttpd {
    class session;
    using asio_socket = asio::ip::tcp::socket;
    using request_handler = std::function<void(std::shared_ptr<session> session)>;
    using write_done_handler = std::function<void(std::shared_ptr<session> session)>;
    using error_handler = std::function<void(const std::string& tag, std::shared_ptr<session> session, const std::error_code& ec)>;

    struct config {
        std::string addr;
        std::uint16_t port = 80;
        bool ssl_on = false;
        std::size_t thread_count = 1;
        bool reuse_address = true;

        std::size_t max_request_size = 16 * 1024;
    };

    namespace detail {
        struct context: asio::noncopyable {
            request_handler on_request;
            config conf;
            error_handler on_error;

            context(const request_handler& handler, const config& conf) : on_request(handler), conf(conf) {}
        };
    }

    class request: asio::noncopyable {
    private:
        request(const detail::context& ctx): _streambuf(ctx.conf.max_request_size) {
        }

    public:
        std::streambuf& body() {
            return _streambuf;
        }

        std::string host() const {
            return header_value_or("host");
        }

        std::string path() const {
            if (_path[0] == '/') {
                return _path;
            }
            auto pos = _path.find('/', 7);
            if (pos == std::string::npos) {
                return "/";
            }
            return _path.substr(pos);
        }

        std::string method() const {
            return _method;
        }

        const std::map<std::string, std::string> headers() const {
            return _headers;
        }

    private:
        bool parse_head() {
            // parse request line
            enum {
                method = 0, path, version, expecting_new_line, new_line_start, field_name, field_value,
                expecting_new_line2,
            } state = method;
            std::string name, value;
            while (true) {
                auto input = _streambuf.sbumpc();
                switch (state) {
                case method:
                    if (!std::isalpha(input)) {
                        if (input == ' ') {
                            state = path;
                            break;
                        }
                        return false;
                    }
                    _method.push_back(std::toupper(input));
                    break;
                case path:
                    if (std::iscntrl(input)) {
                        return false;
                    }
                    if (input == ' ') {
                        if (_path.empty()) {
                            return false;
                        }
                        state = version;
                        break;
                    }
                    _path.push_back(input);
                    break;
                case version:
                    if (!std::isprint(input)) {
                        if (input == '\r' &&_version[0] == 'H' && _version[1] == 'T' && _version[2] == 'T' && _version[3] == 'P'
                            && _version[4] == '/' && std::isdigit(_version[5]) && _version[6] == '.' && std::isdigit(_version[7])) {
                            _version = _version.substr(5);
                            state = expecting_new_line;
                            break;
                        }
                        return false;
                    }
                    _version.push_back(std::toupper(input));
                    break;
                case expecting_new_line:
                    if (input != '\n') {
                        return false;
                    }
                    state = new_line_start;
                    break;
                case new_line_start:
                    if (input == '\r') {
                        state = expecting_new_line2;
                        break;
                    }
                    state = field_name;
                    // new field case, clear name and value
                    name.clear();
                    value.clear();
                    // no break here, fallthrough
                case field_name:
                    if (std::iscntrl(input) || input == ' ') {
                        return false;
                    }
                    if (input == ':') {
                        name = utils::string::to_lower(name);
                        if (_headers.find(name) != _headers.end()) {
                            return false;
                        }
                        state = field_value;
                        break;
                    }
                    name.push_back(input);
                    break;
                case field_value:
                    if (std::iscntrl(input)) {
                        if (input == '\r') {
                            auto pos = value.find_last_not_of(' ');
                            if (pos != std::string::npos) {
                                value.resize(pos + 1);
                            }
                            _headers[std::move(name)] = std::move(value);
                            state = expecting_new_line;
                            break;
                        }
                        return false;
                    }
                    if (input == ' ' && value.empty()) {
                        break;
                    }
                    value.push_back(input);
                    break;

                case expecting_new_line2:
                    return input == '\n';

                default:
                    return false;
                }
            }
        }

        std::string header_value_or(const std::string& name, const std::string& fallback = {}) const {
            return _headers.find(name) == _headers.end() ? "" : _headers.at(name);
        }

        std::size_t content_length() const {
            auto iter = _headers.find("content-length");
            if (iter == _headers.end()) {
                return 0;
            }
            return std::atoi(iter->second.c_str());
        }

        asio::streambuf& streambuf() {
            return _streambuf;
        }

    private:
        // raw request data holder
        asio::streambuf _streambuf;
        // request line
        std::string _method;
        std::string _path;
        std::string _version;
        // request header fields
        std::map<std::string, std::string> _headers;

        friend class session;
    };

    class response: asio::noncopyable {
    private:
        using async_write_handler = std::function<void(std::shared_ptr<asio::streambuf> streambuf, write_done_handler&& handler)>;

    public:
        response(const detail::context& ctx, async_write_handler&& handler): _async_write(std::move(handler)) {
        }

    public:
        response& write_status(status_code code, const std::string& message = {}) {
            _status_code = code;
            _status_message = message.empty() ? reason_phrase(code) : message;
            return *this;
        }

        response& write_header(const std::string& name, const std::string& value) {
            auto normalized_name = utils::string::to_lower(name);
            if (name == "set-cookie") {
                _multipleHeaders[normalized_name].push_back(value);
            } else {
                _headers[normalized_name] = value;
            }
            return *this;
        }

//         response& write_thunked_body(const void* data, std::size_t size) {
//             return *this;
//         }
// 
//         void write_thunked_body_end() {
// 
//         }

        void write_body(const char* str, write_done_handler&& handler = {}) {
            write_body(str, std::strlen(str), std::move(handler));
        }

        void write_body(const std::string& str, write_done_handler&& handler = {}) {
            write_body(str.data(), str.size(), std::move(handler));
        }

        void write_body(const void* data = nullptr, std::size_t size = 0, write_done_handler&& handler = {}) {
            auto iter = _headers.find("content-length");
            if (iter == _headers.end()) {
                _headers["content-length"] = std::to_string(size);
            }
            auto streambuf = std::make_shared<asio::streambuf>();
            streambuf->prepare(size);
            streambuf->sputn((const char*)data, size);
            write_head([this, streambuf, handler = std::move(handler)](auto) {
                _async_write(std::move(streambuf), [handler = std::move(handler)](auto session) {
                    if (handler) {
                        handler(session);
                    }
                });
            });
        }


    private:
        void write_head(write_done_handler&& handler) {
            if (_status_code == status_code::bad) {
                write_status(status_code::ok);
            }
            _headers["server"] = "ehttpd";
            auto streambuf = std::make_shared<asio::streambuf>();
            streambuf->prepare(1024);
            std::ostream os(streambuf.get());
            os << "HTTP/1.1 " << static_cast<int>(_status_code) << " " << _status_message << "\r\n";
            for (auto& header : _headers) {
                os << header.first << ": " << header.second << "\r\n";
            }
            for (auto& header : _multipleHeaders) {
                for (auto& value : header.second) {
                    os << header.first << ": " << value << "\r\n";
                }
            }
            os << "\r\n";
            _async_write(std::move(streambuf), [handler = std::move(handler)](auto session) {
                handler(session);
            });
        }

    private:
        status_code _status_code = status_code::bad;
        std::string _status_message;
        std::map<std::string, std::string> _headers;
        std::map<std::string, std::vector<std::string>> _multipleHeaders;
        async_write_handler _async_write;
    };

    namespace detail {
        class connection : public asio::noncopyable {
        public:
            connection(std::unique_ptr<asio_socket>&& socket): _socket(std::move(socket)) {}

        public:
            asio_socket& socket() {
                return *_socket;
            }

        private:
            std::unique_ptr<asio_socket> _socket;
        };
    }

    class session : public asio::noncopyable, public std::enable_shared_from_this<session> {
    public:
        session(std::unique_ptr<detail::connection>&& connection, const detail::context& ctx)
            : _connection(std::move(connection))
            , _context(ctx)
            , _request(ctx)
            , _response(ctx, [this](auto& sb, auto&& handler) { write_response(sb, std::move(handler)); }) {

        }

    public:
        void read_request() {
            asio::async_read_until(_connection->socket(), _request.streambuf(), "\r\n\r\n", [this, self = shared_from_this()](const auto &ec, auto bytes_transferred) {
                if (_request.streambuf().size() == _request.streambuf().max_size()) {
                    write_error(status_code::request_entity_too_large);
                    return;
                }
                if (ec) {
                    write_error(status_code::internel_server_error);
                    return;
                }

                auto additional_bytes = _request.streambuf().size() - _request.content_length();

                // parse header
                if (!_request.parse_head()) {
                    write_error(status_code::bad_request);
                    return;
                }

                // no implement the request with chunked Transfer-Encoding
                auto content_length = _request.content_length();
                if (content_length > additional_bytes) {
                    asio::async_read(_connection->socket(), _request.streambuf(), asio::transfer_exactly(content_length - additional_bytes), [this, self](const auto &ec, auto bytes_transferred) {
                        _context.on_request(shared_from_this());
                    });
                } else {
                    _context.on_request(shared_from_this());
                }
            });
        }

        request& req() {
            return _request;
        }

        response& res() {
            return _response;
        }

    private:
        void write_error(status_code code) {
            _response.write_status(code);
            _response.write_header("connection", "close");
            _response.write_header("content-type", "text/plain");
            _response.write_body(reason_phrase(code));
        }

        void write_response(std::shared_ptr<asio::streambuf> streambuf, write_done_handler&& handler) {
            asio::async_write(_connection->socket(), *streambuf, [this, self = shared_from_this(), streambuf, handler = std::move(handler)](auto ec, auto) {
                if (ec) {
                    // on error
                }
                handler(shared_from_this());
            });
        }
    private:
        const detail::context& _context;
        std::unique_ptr<detail::connection> _connection;
        request _request;
        response _response;
    };



    class server {
    public:
        server(const request_handler& handler, const config& conf) 
            : _context(handler, conf), _acceptor(_io_service) {}

    private:
        server(const server&) = delete;
        server& operator=(const server&) = delete;

    public:
        void listen() {
            auto& conf = _context.conf;
            if (conf.port == 0) {
                throw ehttpd_bad_config_exception("port", std::to_string(conf.port), "1-65535");
            }

            asio::ip::tcp::endpoint endpoint;
            if (!conf.addr.empty()) {
                endpoint = asio::ip::tcp::endpoint(asio::ip::address::from_string(conf.addr), conf.port);
            } else {
                endpoint = asio::ip::tcp::endpoint(asio::ip::tcp::v4(), conf.port);
            }

            try {
                _acceptor.open(endpoint.protocol());
                _acceptor.set_option(asio::socket_base::reuse_address(conf.reuse_address));
                _acceptor.bind(endpoint);
                _acceptor.listen();
            } catch (const asio::system_error& ec) {
                throw ehttpd_exception(ec.what());
            }

            accept_next();

            auto thread_count = conf.thread_count < 1 ? 1 : conf.thread_count;

            std::vector<std::thread> threads;
            for (std::size_t i = 1; i < conf.thread_count; i++) {
                threads.emplace_back(std::thread([this]() {
                    asio::error_code ec;
                    _io_service.run(ec);
                }));
            }

            try {
                _io_service.run();
            } catch (const asio::error_code& ec) {
                throw ehttpd_exception(ec.message());
            }

            for (auto& t : threads) {
                t.join();
            }
        }

        void stop() {
            _acceptor.close();
            _io_service.stop();
        }

        server& on_error(const error_handler& handler) {
            _context.on_error = handler;
            return *this;
        };

    private:
        void accept_next() {
            auto socket = std::make_unique<asio_socket>(_io_service);
            auto& asio_socket = *socket;
            _acceptor.async_accept(asio_socket, [this, socket = std::move(socket)](const auto& ec) mutable {
                if (ec) {
                    // error occured
                    if (ec == asio::error::operation_aborted) {
                        // service has stopped
                        return;
                    }
                    // notify
                    on_error("accept", nullptr, ec);
                    accept_next();
                    return;
                }

                // all the network context and operation are in the socket object
                // convert the socket object the connection object
                on_new_connection(std::make_unique<detail::connection>(std::move(socket)));

                accept_next();
            });
        }

        void on_new_connection(std::unique_ptr<detail::connection>&& connection) {
            // create new session
            std::make_shared<session>(std::move(connection), _context)->read_request();
        }

        void on_error(const std::string& tag, std::shared_ptr<session> session, const asio::error_code& ec) {
            if (_context.on_error) {
                _context.on_error(tag, std::move(session), ec);
            }
        }

    private:
        detail::context _context;
        asio::io_service _io_service;
        asio::ip::tcp::acceptor _acceptor;
//         std::set<std::shared_ptr<session>> _session;
//         std::mutex _mutex;
    };
}

#endif
