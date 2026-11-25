// Analyzer minimal COMPLETE type (row 23g copy-local header): C's
// analyzer_command.h :36 carries ONLY the forward `class Analyzer;` — the
// class home (analyzer.cc) NEVER landed. The row's execute(Analyzer&)
// body NEVER dereferences its parameter; the probe needs ONLY a
// referenceable object (the reference-forming face — ZERO faked Analyzer
// behavior, the cited deviation). BOTH probe TUs + the witness include
// THIS header AFTER analyzer_command.h (the forward-decl + complete-def
// same-scope face).
#ifndef ANALYZER_MIN_H
#define ANALYZER_MIN_H
class Analyzer {
public:
    virtual ~Analyzer() = default;
};
#endif
