#include "taskspy.h"

#include "AutonomOS/Units/prefix.h"

using namespace AOS;
using namespace AOS::Test;

TaskSpy::TaskSpy()
    : m_runs(0u)
    , m_runMin(0u)
    , m_runMax(0u)
{
}

void TaskSpy::computeStatistics()
{
    computeBasedOnProvidedSteps();
    computeBasedOnLoggedSteps();
}

bool TaskSpy::executed() const
{
    return m_runs > 0u;
}

uint64_t TaskSpy::runs() const
{
    return m_runs;
}

uint64_t TaskSpy::maxRunNumber() const
{
    return m_runMax;
}

uint64_t TaskSpy::minRunNumber() const
{
    return m_runMin;
}

const std::vector<Time> &TaskSpy::steps() const
{
    return m_steps;
}

const std::vector<Time> &TaskSpy::loggedSteps() const
{
    return m_logged;
}

Time TaskSpy::minStep() const
{
    return m_min;
}

Time TaskSpy::maxStep() const
{
    return m_max;
}

Time TaskSpy::averageStep() const
{
    return m_average;
}

Time TaskSpy::minLoggedStep() const
{
    return m_loggedmin;
}

Time TaskSpy::maxLoggedStep() const
{
    return m_loggedmax;
}

Time TaskSpy::averageLoggedStep() const
{
    return m_loggedaverage;
}

void TaskSpy::cycle(const Time &step)
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

void TaskSpy::computeBasedOnLoggedSteps()
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

void TaskSpy::computeBasedOnProvidedSteps()
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
