#include "temporalspy.h"

#include "AutonomOS/Units/prefix.h"

using namespace AOS;
using namespace AOS::Test;

TemporalSpy::TemporalSpy()
    : m_runs(0u)
    , m_runMin(0u)
    , m_runMax(0u)
{
}

void TemporalSpy::computeStatistics()
{
    computeBasedOnProvidedSteps();
    computeBasedOnLoggedSteps();
}

bool TemporalSpy::executed() const
{
    return m_runs > 0u;
}

uint64_t TemporalSpy::runs() const
{
    return m_runs;
}

uint64_t TemporalSpy::maxRunNumber() const
{
    return m_runMax;
}

uint64_t TemporalSpy::minRunNumber() const
{
    return m_runMin;
}

const std::vector<Time> &TemporalSpy::steps() const
{
    return m_steps;
}

const std::vector<Time> &TemporalSpy::loggedSteps() const
{
    return m_logged;
}

Time TemporalSpy::minStep() const
{
    return m_min;
}

Time TemporalSpy::maxStep() const
{
    return m_max;
}

Time TemporalSpy::averageStep() const
{
    return m_average;
}

Time TemporalSpy::minLoggedStep() const
{
    return m_loggedmin;
}

Time TemporalSpy::maxLoggedStep() const
{
    return m_loggedmax;
}

Time TemporalSpy::averageLoggedStep() const
{
    return m_loggedaverage;
}

void TemporalSpy::step(const Time &step)
{
    m_steps.push_back(step);
    auto now = std::chrono::system_clock::now();
    if(m_runs++ > 0)
    {
        auto diff = now - m_prev;
        m_logged.push_back(Time(diff));
    }
    else
        m_logged.push_back(step);
    m_prev = now;
}

void TemporalSpy::computeBasedOnLoggedSteps()
{
    if(m_logged.empty())
        return;
    Time time;
    m_loggedmin = m_logged.front();
    m_loggedmax = m_logged.front();
    for(auto step : m_logged)
    {
        time += step;
        if(m_loggedmin > step)
            m_loggedmin = step;
        if(m_loggedmax < step)
            m_loggedmax = step;
    }
    m_loggedaverage = time / m_logged.size();
}

void TemporalSpy::computeBasedOnProvidedSteps()
{
    if(m_steps.empty())
        return;
    Time time;
    m_min = m_steps.front();
    m_max = m_steps.front();
    uint64_t i = 0u;
    for(auto step : m_steps)
    {
        i++;
        time += step;
        if(m_min > step)
        {
            m_min = step;
            m_runMin = i;
        }
        if(m_max < step)
        {
            m_max = step;
            m_runMax = i;
        }
    }
    m_average = time / m_steps.size();
}
