/*
 * foo.cpp
 *
 *  Created on: Nov 8, 2016
 *      Author: francis
 */
#include "foo.h"
#include <iostream>

using namespace std;

Foo::Foo(function<void ()> fn, bool debug) :
	m_fn(fn), m_debug(debug)
{

}

void Foo::foo(int depth)
{
	volatile int d = depth - 1;
	if (m_debug)
		cout << "foo " << d << endl;
	if (d > 0)
		bar(d);
	else
		m_fn();
}

void Foo::bar(int depth)
{
	volatile int d = depth - 1;
	if (m_debug)
		cout << "bar " << d << endl;
	if (d > 0)
		baz(d);
	else
		m_fn();
}

void Foo::baz(int depth)
{
	volatile int d = depth - 1;
	if (m_debug)
		cout << "baz " << d << endl;
	if (d > 0)
		foo(d);
	else
		m_fn();
}
