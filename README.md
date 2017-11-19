# Requirement
* C++ compiler with C++14 suppported
* Asio library

# Usage
* Setup header file search path for asio library..
* Copy ehttpd.hpp to your project.
* include it and enjoy yourself.

# Getting Start
```
try {
    ehttpd::server([](auto session) {
        auto& req = session->req();
        std::cout << req.method() << " " << req.path() << std::endl;
        auto& res = session->res();
        res.write_body("hello world");
    }, {}).on_error([](auto& tag, auto session, auto& ec) {
        std::cout << "ERROR - TAG:" << tag << ", MESSAGE:" << ec.message() << std::endl;
    }).listen();
} catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
}
```
See examples for more details.

# API Reference
RTFSC

# License
MIT