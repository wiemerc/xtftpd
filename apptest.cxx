#include <iostream>
#include "Poco/Util/ServerApplication.h"
#include "Poco/Util/IntValidator.h"
#include "Poco/Logger.h"
#include "Poco/LogStream.h"
#include "Poco/Format.h"


//
// some helper functions to make logging more convenient
//
static inline void LOG_INFO (Poco::Logger &logger, const std::string &fmtstr)
{
    logger.information (fmtstr, __FILE__, __LINE__);
}

static inline void LOG_INFO (Poco::Logger &logger, const std::string &fmtstr, const Poco::Any &arg1)
{
    logger.information (Poco::format (fmtstr, arg1), __FILE__, __LINE__);
}

static inline void LOG_INFO (Poco::Logger &logger, const std::string &fmtstr, const Poco::Any &arg1, const Poco::Any &arg2)
{
    logger.information (Poco::format (fmtstr, arg1, arg2), __FILE__, __LINE__);
}


class AppTest : public Poco::Util::ServerApplication
{
    public:
        void initialize (Poco::Util::Application &self)
        {
            std::cerr << "initialize() called" << std::endl;
            loadConfiguration();
            Poco::Util::Application::initialize (self);
        }


        void defineOptions (Poco::Util::OptionSet &options)
        {
            Poco::Util::ServerApplication::defineOptions (options);

            options.addOption (Poco::Util::Option ("port", "p", "server port for diverted packets")
                .required (false)
                .repeatable (false)
                .argument ("port")
                .binding ("TFTPServer.port")
                .validator (new Poco::Util::IntValidator (1000, 65535)));
        }


        int main (const std::vector<std::string> &args)
        {
            std::cerr << "main() called" << std::endl;
            std::cerr << "arguments:" << std::endl;
            for (std::vector<std::string>::const_iterator it = args.begin(); it != args.end(); it++)
                std::cerr << *it << std::endl;

            std::cerr << "configuration:" << std::endl;
            std::cerr << "server port = " << std::to_string (config().getInt ("server.port", 9999)) << std::endl;

            Poco::Logger &logger = Poco::Logger::root();
            LOG_INFO (logger, "just for information");
            LOG_INFO (logger, "a = %d, b = %s", 1, std::string ("abc"));

            return EXIT_OK;
        }
};


int main (int argc, char ** argv)
{
    AppTest app;
    return app.run (argc, argv);
}

