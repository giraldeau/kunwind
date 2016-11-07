/*
 * foo.h
 *
 *  Created on: Nov 8, 2016
 *      Author: francis
 */

#ifndef LIBKUNWIND_TESTS_FOO_H_
#define LIBKUNWIND_TESTS_FOO_H_

#include <functional>

using namespace std;

#define noinline __attribute__((noinline))

class Foo {
public:
    Foo(std::function<void ()> fn, bool debug = false);
    void foo(int depth);
    void bar(int depth);
    void baz(int depth);

private:
    function<void ()> m_fn;
    bool m_debug;
};


#endif /* LIBKUNWIND_TESTS_FOO_H_ */
