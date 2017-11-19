#include <ehttpd.hpp>
#include <iostream>
#include <string>
#include <stdlib.h>

int main() {
    try {
        ehttpd::server([](auto session) {
            auto& req = session->req();
            std::cout << req.method() << " " << req.path() << std::endl;
            for (auto& header : req.headers()) {
                std::cout << header.first << ": " << header.second << std::endl;
            }
            std::cout << std::endl;
            if (req.body().in_avail() > 0) {
                std::istream is(&req.body());
                std::copy(std::istream_iterator<char>(is), std::istream_iterator<char>(), std::ostream_iterator<char>(std::cout));
            }
            
            
            auto& res = session->res();
            res.write_body("hello world");

        }, {}).on_error([](auto& tag, auto session, auto& ec) {
            std::cout << "ERROR - TAG:" << tag << ", MESSAGE:" << ec.message() << std::endl;
        }).listen();
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
    }

    system("pause");
    return 0;
}