# FP Refactoring Example

This is an example of refactoring some rather complex logic in a
Spring Security AccessDecisionVoter which decides if a user should
gain access, be denied access, or if the voter abstains from deciding.

The class in question is the SecurityLevelVoter, and the "before"-version
can be found in the package com.github.runeflobakk.security.voter.old,
whereas the refactored version is in com.github.runeflobakk.security.voter.
The unit test can easily switch which voter it excercises simply by
adding or removing ".old" to the voter's import statement in the test.
