#include "LogBase.h"
#include <iostream>

namespace util {

LogBase* LogBase::instance = NULL;

LogBase* LogBase::Inst() {
    if (instance == NULL) {
        instance = new LogBase();
    }

    return instance;
}


LogBase::LogBase() {
    m_enabled[log::verbose]	= false;
    m_enabled[log::info] = true;
    m_enabled[log::warning]	= true;
    m_enabled[log::error] = true;
    m_enabled[log::timer] = false;
}


LogBase::~LogBase() {}


void LogBase::Log(const log::Fmt& msg, log::Severity s) {
    if (IsEnabled(s) && !IsEnabled(log::timer)) {
      std::cout << msg.str() << "\n";
    }
}


bool LogBase::Enable(log::Severity s, bool enable) {
    bool prev = m_enabled[s];
    m_enabled[s] = enable;

    return prev;
}


void LogBase::DisableAll(bool b) {
    m_enabled[log::verbose]	= b;
    m_enabled[log::info] = b;
    m_enabled[log::warning]	= b;
    m_enabled[log::error] = b;
    m_enabled[log::timer] = b;
}


bool LogBase::IsEnabled( log::Severity s ) const {
    return m_enabled[s];
}


void Log(const string& str, log::Severity s) {
    LogBase::Inst()->Log(log::Fmt(str), s);
}


void DisableAllLogs(bool b) {
    LogBase::Inst()->DisableAll(b);
}



}
