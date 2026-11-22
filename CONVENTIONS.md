# Coding conventions

The goal is a codebase that is lean (small, readable, fast) with no loss of features, capability or speed. These
conventions are written for people; they apply to everyone, including the agents that write much of the code. This
file is the full style specification of mdnspp. `.clang-format` holds the mechanical formatting rules, `.clang-tidy`
the naming rules. When something here conflicts with habit, this file wins.

## No planning artifacts

Planning lives in the planning tools, never in the code. Never reference an identifier, key or label produced by a
planning or issue-tracking tool (phase, milestone, plan, task or requirement numbers, invariant or threat labels)
anywhere in the codebase: identifiers, test names and tags, comments, documentation, examples and commit messages.

State the thing itself, not its planning label. A comment explaining a real invariant says it in plain words ("the
receive loop closes before the members die"); it never cites a label. If a reader would have to open a planning
document to decode a comment, the comment is wrong. The same goes for narrative scaffolding from how the code was
built ("the slice", "the gate", "relocated from ...", "X was the example"), which means nothing to a reader of the
finished code. Cut it.

## Language and portability

- Idiomatic C++20 (`CMAKE_CXX_STANDARD 20`, extensions off). Use the language; do not reinvent what the standard
  library or asio already do well.
- The code must compile and run on macOS, Linux and Windows. Platform-specific code stays behind preprocessor guards
  in the units that wrap the operating system: the default policy's socket and context, the native socket, interface
  and NIC monitor units under `detail/`, and `detail/platform.h`. Protocol logic and the engines stay portable.
- Follow the conventions of modern C++ libraries (standard library, asio, boost). Existing project conventions take
  precedence. If you are unsure, or a popular idiom contradicts the project, ask rather than guess.
- The code compiles clean under the warning set in the top-level `CMakeLists.txt` (`-Wall -Wextra -Wpedantic
  -Wshadow -Wconversion -Wsign-conversion -Wold-style-cast` and more; `/W4 /permissive-` on MSVC).

## File and function size

These limits and the comment rules apply to every code file: C++, CMake (`CMakeLists.txt`, `*.cmake`, `*.cmake.in`)
and shell (`*.sh`). Markdown is exempt.

The limits count lines including comments and blank lines; the budget is the whole thing as it sits on screen:

| Unit                                                      | Target     | Hard ceiling |
| --------------------------------------------------------- | ---------- | ------------ |
| Function, lambda, `TEST_CASE`, `SCENARIO`, CMake function | 5-15 lines | 25 lines     |
| File                                                      | ~100 lines | 200 lines    |

Readability is the goal, not SOLID or DRY orthodoxy. Group code that is read together. Split where it genuinely
separates responsibilities, never to chase a number.

Each scope does one thing, and the smaller that one thing is, the cleaner the code reads: a library does one thing
(the core, the asio policy, encryption, the in-process bus, the mock test policy), a namespace groups the types and
functions working toward one thing, a class does one thing, a function does one thing. A unit that runs over its
ceiling is usually the "one thing" drawn too broad: decompose it, do not widen the budget.

Forbidden:

- **Salami-slicing**: carving a cohesive unit into fragments just to fit a limit.
- **One-function files**: a file that exists only to hold a single function.
- **Artificial purity**: a wrapper or layer that adds indirection without separating a real responsibility.

Keep public headers lean by moving internal helpers into a `detail/` directory and the `detail::` namespace; a
public class template may derive privately from a `detail::` engine that carries its state and logic. A `detail/`
file is still a real file and obeys these same rules.

Enforcement: review. No tool in the build or in CI checks file or function size. A change is not done until it is
within budget or its overage is a registered exception.

### Exceptions

A file or function may exceed its ceiling only when it is a single cohesive whole that splitting would harm:
scattering shared state across files, or forcing an artificial-purity layer. An exception is a considered decision,
not a fallback; prefer decomposition, and reach for an exception only when decomposition would make the code worse.

Every exception is registered in `EXCEPTIONS.md` at the repository root, the single, complete list of every
sanctioned over-limit unit, each with its justification. No unit is registered at present, so the file does not
exist yet; a unit over its ceiling that is not listed there is a defect to fix, not an exception. There is no
in-code marker: the justification is bookkeeping, and bookkeeping never belongs in the code.

## Comments

The codebase is written for people to read. A comment must say something the code itself cannot. The default is no
comment: clear names and signatures carry the meaning.

Write a comment only when it does one of:

- **(a)** cites a source: a paper, RFC, spec, URL, bug report or standards clause (`RFC 6762 section 7.1`);
- **(b)** names a non-obvious algorithm or technique so a reader can look it up;
- **(c)** explains a non-obvious design choice in one or two sentences: a bug workaround, a deliberate tradeoff, or
  a contract, ordering, side effect or invariant that is real but not visible from the code.

Delete everything else. Never write:

- comments that restate a name, signature, type or obvious control flow in more words;
- tables or lists that transcribe the lines of code beneath them (each field or function a builder adds);
- sign-posting or narration aimed at a reader navigating the code ("this section does X", "first we ... then we");
- bookkeeping or process markers: size justifications, ledgers, "see the doc" pointers, anything whose audience is
  the maintainer's process rather than the code's reader;
- design history or example association ("relocated from ...", "X was the example").

Library headers carry no API doc comments (`///`, `/** */`). The public API is documented under `docs/`: one page
per type in `docs/api/` and the topic guides beside it. A contract a caller needs (error codes, preconditions,
threading, lifetime) goes on the type's page, not into the header.

A comment that merely repeats the next line is noise: it steals screen space, competes with the code and rots out of
sync. Keep a multi-line comment tight, with no blank `//` separator lines padding it out.

A comment longer than a short tag goes on its own line above the code it explains, never trailing. A long trailing
comment crowds the statement and forces the formatter to wrap the code beneath it. A brief trailing tag on a data
line (a unit, an enumerator's value) is fine where it reads as part of that line.

Comments count toward the size budget. A file that is 30% comments is usually 30% over-commented, not a candidate
for a bigger budget: trim first.

## Includes

Internal project includes (`#include "..."`) come first, third-party libraries second, standard-library headers
third. Order deviates from this only when something must precede something else for a real reason (a platform
header that must come before another).

- The three major sections are separated by one blank line, and only one blank line ever separates two groups.
- Within a major section, includes are grouped by folder, one blank line between groups. In the project section the
  file's own subsystem (its own folder) comes first, then the remaining project folder groups:
  `"mdnspp/records.h"` and the other `"mdnspp/..."` includes, then the `"mdnspp/detail/..."` group.
- An angle-bracket include groups by its top-level folder: `<catch2/catch_test_macros.hpp>` and
  `<catch2/generators/catch_generators.hpp>` share the `catch2` group, and the project's own headers included with
  angle brackets (tests, examples, install consumers) share one `mdnspp` group. A top-level header whose stem names
  such a folder joins it: `<asio.hpp>` goes with `<asio/...>`.
- Within a group, includes are sorted by the length of the file name (the part after the last `/`), shortest first;
  file names of equal length sort alphabetically.

## Naming

`.clang-tidy` encodes the naming rules (`readability-identifier-naming`):

- `lower_case` for namespaces, classes, structs, enums and enumerators, type aliases, concepts, functions, variables,
  parameters and members.
- Private and protected data members take an `m_` prefix; public members of an aggregate do not.
- Template parameters are `CamelCase` (`P`, `Clock`); macros are `UPPER_CASE`.
- A member holding a callback or hook (a `move_only_function`) takes a `_cb` suffix and groups with the other
  callbacks in the member list: the suffix marks it as an injected behavior, not state.

## Construction

- Every class initializes its members in the constructor's init list, never in-declaration: one place, one source of
  truth, so two defaults can never drift apart. A member that wants a default gets it in the init list; a class
  without a constructor that is not a pure aggregate declares one to carry it.
- Exception: a pure aggregate (no user-declared constructor, no private or protected data members, no invariants, no
  virtual functions or bases) that callers build with designated initializers keeps its member defaults
  in-declaration, so callers name only the fields they override (`service_options{.send_goodbye = false}`) and every
  other field keeps its default. The typical cases are the options and configuration structs of the public API and
  the `detail::` aggregates that tests build with designated initializers. Adding a constructor to carry the defaults
  would forfeit designated initialization; do not.
- The constructor's init list is written in member-declaration order. Members initialize in declaration order
  whatever the init-list order, so the two must agree (no `-Wreorder`). A member consumed by another member's
  constructor must be declared before its consumer, and that dependency overrides the member triangle below.

## Class layout

Order a class body so the data is visible before the operations on it:

```
class T
{
    // leading private nested helper types (if any)

public:
    constructor(s)
    public functions

private:
    members          // data first, right after private:
    private functions
};
```

A private nested helper type a class needs may lead the class body, before `public:`. The member triangle (below)
orders the members within the leading private data block, subject to the initialization-order constraint in
**Construction**. Separate each member function from the next with one blank line; pack the data members together.

## Types and attributes

- **Spell out return types.** Do not write `auto` as a function's return type: the named type is what a reader looks
  for first. The only exception is a genuinely unspellable type (a lambda or closure). `auto` for a local variable is
  fine where the initializer makes the type obvious.
- **No `[[nodiscard]]`, ever.** Do not decorate declarations with attributes the compiler does not require.
- **Fixed-width integers** (`uint8_t`, `int32_t`, `uint32_t`, ...) instead of the plain primitives, and `std::size_t`
  for sizes, counts and indices. No platform-specific aliases or macros where a fixed-width type fits, except where a
  platform convention requires one (a socket handle, a third-party signature such as libsodium's
  `unsigned long long` lengths).

## Header guards and namespaces

- Use header guards, not `#pragma once`. Format: `HPP_GUARD_<NAMESPACE>_<FOLDER>_FILENAME_H`, for example
  `HPP_GUARD_MDNSPP_DETAIL_RECV_LOOP_H` for `mdnspp/detail/recv_loop.h` and `HPP_GUARD_MDNSPP_BASIC_SERVICE_SERVER_H`
  for `mdnspp/basic_service_server.h`.
- Do not write a `// namespace X` comment after a closing namespace brace.
- Do not write a comment after `#endif` restating the guard macro.

## API design

- Distinguish three things and never conflate them: required (no default), required-with-default (the override is
  optional) and `std::optional` (absence is itself meaningful, such as `socket_options::interface_name`). Do not use
  `std::optional` as a stand-in for a default.

## Lifetimes and ownership

- Structural, single-owner lifetimes. The owner sequences teardown.
- **Raw pointers are an anti-pattern: avoid them as far as possible.** Use `std::unique_ptr` for sole ownership and
  `std::shared_ptr` for genuinely shared ownership; for everything else, pass and store references. An owner holds
  the long-lived utilities and hands them out by reference (a context object the parts reach through), so a
  non-owner never needs a pointer. A raw pointer survives only where absence is a real, modeled state (a nullable
  lookup result), and even there prefer a reference or `std::optional` where it fits.
- A non-owning relationship that must outlive its holder is a reference, not a raw pointer. Store it as
  `std::reference_wrapper<T>` when it lives in a container that needs assignability.
- No `std::shared_from_this` or `std::enable_shared_from_this`.

## Formatting and tooling

- `.clang-format` encodes the mechanical rules: 120-column lines, Allman braces (lambda bodies included), no space
  before a parenthesis (`if(`, `for(`), `template <` with a space, `case` labels flush with their `switch`,
  constructor initializers one per line with a leading comma, `T &name` and `T *name`, comments never reflowed, and
  includes left unsorted so the hand-kept order above holds. Use it for new and changed code. It is not run in CI and
  the existing tree has not been reformatted to it; a format run over existing code still reports hand-kept shapes
  (wrapped parameter lists, hand-aligned enumerator values and designated initializers, collapsed or expanded short
  functions). Do not reformat code a change does not otherwise touch.
- `.clang-tidy` is the linter: clang-analyzer, bugprone, concurrency and performance checks plus the naming rules. CI
  runs it over the compile-test translation units, which include the whole public header surface, and reports its
  findings without failing the build.
- Stream output ends lines with `std::endl` (`.clang-tidy` disables `performance-avoid-endl` for this reason).

### Shape (readability guidelines, not rigid rules)

These shape the code for the human eye. They are judgment calls: a case that reads better the other way is a fine
exception. The point is to make the next name easy to find.

- **Downward waterfall.** When a signature or declaration wraps, each continuation line is longer than or equal to
  the one above it, so the wrapped arguments slope downward and the eye falls to the next one.
- **Member triangle.** Order a class's members by overall declaration-line length, shortest first, so the members
  form a downward slope. A single space precedes each name; names are not aligned into a column, and neither are
  consecutive assignments. Semantic grouping wins when it helps: keep the callbacks together even if a shorter line
  lands among them. The triangle yields to initialization order (see **Construction**).
- **Logical blank lines.** A blank line inside a function separates logical parts (set-up from the work, one phase
  from the next) the way a paragraph break does.

## English

American spelling: "stabilizing", not "stabilising"; "color", not "colour"; "center", not "centre".

## Commit messages

Format:

```
{Prefix}: {summary sentence}.

- {what was done, one line per item}
- {another item if applicable}
```

The summary line is brief and descriptive; the bullet list expands on it. A single-item commit may omit the bullets.
Allowed prefixes: **Feature, Fix, Refactor, Build, Docs, Examples, Optimization, Test, WIP**. Use `WIP` when the
commit does not compile. A change of behavior or of the public API is named plainly in a bullet.

The no-planning-artifacts rule applies to commit messages too: never reference a phase, plan, task or requirement
number, or any other planning-tool artifact, in a commit message.
