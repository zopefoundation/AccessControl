# The code in this file is executed after being compiled as restricted code,
# and given a globals() dict with our idea of safe builtins, and the
# Zope production implementations of the special restricted-Python functions
# (like _getitem_ and _getiter_, etc).
#
# This isn't trying to provoke security problems, it's just trying to verify
# that Python code continues to work as intended after all the transformations,
# and with all the special wrappers we supply.


def f1():
    try:
        range_ = xrange
    except NameError:  # Py3
        range_ = range

    iterator = iter(range_(3))
    assert next(iterator) == 0
    assert next(iterator) == 1
    assert next(iterator) == 2
    try:
        next(iterator)
    except StopIteration:
        pass
    else:  # pragma: no cover , Safety belt
        assert 0, "expected StopIteration"


f1()


def f2():
    assert list(map(lambda x: x + 1, range(3))) == list(range(1, 4))


f2()


def f3():
    assert list(filter(None, range(10))) == list(range(1, 10))


f3()


def f4():
    assert [i + 1 for i in range(3)] == list(range(*(1, 4)))


f4()


def f5():
    def add(a, b):
        return a + b

    x = range(5)
    result = reduce(add, x, 0)  # noqa, We have this as guarded_reduce
    assert sum(x) == result


f5()


def f6():
    class C:
        def display(self):
            return str(self.value)

    c1 = C()
    c2 = C()
    c1.value = 12
    assert getattr(c1, 'value') == 12
    assert c1.display() == '12'
    assert not hasattr(c2, 'value')
    setattr(c2, 'value', 34)
    assert c2.value == 34
    assert hasattr(c2, 'value')
    del c2.value
    assert not hasattr(c2, 'value')

    # OK, if we can't set new attributes, at least verify that we can't.
    # try:
    #     c1.value = 12
    # except TypeError:
    #     pass
    # else:
    #     assert 0, "expected direct attribute creation to fail"

    # try:
    #     setattr(c1, 'value', 12)
    # except TypeError:
    #     pass
    # else:
    #     assert 0, "expected indirect attribute creation to fail"

    assert getattr(C, "display", None) == getattr(C, "display")
    delattr(C, "display")

    # try:
    #     setattr(C, "display", lambda self: "replaced")
    # except TypeError:
    #     pass
    # else:
    #     assert 0, "expected setattr() attribute replacement to fail"

    # try:
    #     delattr(C, "display")
    # except TypeError:
    #     pass
    # else:
    #     assert 0, "expected delattr() attribute deletion to fail"


f6()


def f7():
    d = apply(dict, [((1, 2), (3, 4))])  # NOQA: F821 {1: 2, 3: 4}
    methods = [('keys', 'k'),
               ('items', 'i'),
               ('values', 'v')]
    try:
        {}.iterkeys
    except AttributeError:
        pass
    else:
        # Python 2 only:
        methods.extend([
            ('iterkeys', 'k'),
            ('iteritems', 'i'),
            ('itervalues', 'v')])

    expected = {'k': [1, 3],
                'v': [2, 4],
                'i': [(1, 2), (3, 4)]}
    for meth, kind in methods:
        access = getattr(d, meth)
        result = sorted(access())
        assert result == expected[kind], (meth, kind, result, expected[kind])


f7()


def f8():
    import math
    ceil = getattr(math, 'ceil')
    smallest = 1e100
    smallest_index = None
    largest = -1e100
    largest_index = None
    all = []
    for i, x in enumerate((2.2, 1.1, 3.3, 5.5, 4.4)):
        all.append(x)
        effective = ceil(x)
        if effective < smallest:
            assert min(effective, smallest) == effective
            smallest = effective
            smallest_index = i
        if effective > largest:
            assert max(effective, largest) == effective
            largest = effective
            largest_index = i
    assert smallest == 2
    assert smallest_index == 1
    assert largest == 6
    assert largest_index == 3

    assert min([ceil(x) for x in all]) == smallest
    assert max(map(ceil, all)) == largest


f8()


# After all the above, these wrappers were still untouched:
#     ['DateTime', '_print_', 'reorder', 'same_type', 'test']
# So do something to touch them.
def f9():
    d = DateTime()  # NOQA: F821
    print(d)  # this one provoked _print_

    # Funky.  This probably isn't an intended use of reorder, but I'm
    # not sure why it exists.
    assert reorder('edcbaxyz', 'abcdef', 'c') == zip('abde', 'abde')  # NOQA

    assert test(0, 'a', 0, 'b', 1, 'c', 0, 'd') == 'c'  # NOQA: F821
    assert test(0, 'a', 0, 'b', 0, 'c', 0, 'd', 'e') == 'e'  # NOQA: F821
    # Unclear that the next one is *intended* to return None (it falls off
    # the end of test's implementation without explicitly returning anything).
    assert test(0, 'a', 0, 'b', 0, 'c', 0, 'd') is None  # NOQA: F821

    assert same_type(3, 2, 1), 'expected same type'  # NOQA: F821
    assert not same_type(3, 2, 'a'), 'expected not same type'  # NOQA: F821
    return printed  # NOQA: F821


f9()


def f10():
    assert next(iter(enumerate(iter(iter(range(9)))))) == (0, 0)


f10()


def f11():
    x = 1
    x += 1


f11()


def f12():
    assert all([True, True, True]) is True
    assert all([True, False, True]) is False


f12()


def f13():
    assert any([True, True, True]) is True
    assert any([True, False, True]) is True
    assert any([False, False, False]) is False


f13()


def f14():
    """provoke _unpack_sequence_"""
    (a, (b, c)) = (1, (3, (4, 5)))
    assert a == 1
    assert b == 3
    assert c == (4, 5)


f14()
