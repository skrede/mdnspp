#ifndef AOS_TEST_TEMPORALSPY_H
#define AOS_TEST_TEMPORALSPY_H

#include "AutonomOS/Core/Traits/itemporal.h"

#include "AutonomOS/Units/time.h"
#include "AutonomOS/Units/frequency.h"

namespace AOS {
namespace Test {

class TemporalSpy : public ITemporal
{
public:
    TemporalSpy();

    void computeStatistics();

    bool executed() const;
    uint64_t runs() const;
    uint64_t maxRunNumber() const;
    uint64_t minRunNumber() const;

    const std::vector<Time> &steps() const;
    const std::vector<Time> &loggedSteps() const;

    Time minStep() const;
    Time maxStep() const;
    Time averageStep() const;

    Time minLoggedStep() const;
    Time maxLoggedStep() const;
    Time averageLoggedStep() const;

    void step(const Time &step) override;

private:
    uint64_t m_runs;
    uint64_t m_runMin;
    uint64_t m_runMax;
    Time m_min;
    Time m_max;
    Time m_average;
    Time m_loggedmin;
    Time m_loggedmax;
    Time m_loggedaverage;
    std::vector<Time> m_steps;
    std::vector<Time> m_logged;
    std::chrono::time_point<std::chrono::system_clock> m_prev;

    void computeBasedOnLoggedSteps();
    void computeBasedOnProvidedSteps();
};

}
}

#endif
