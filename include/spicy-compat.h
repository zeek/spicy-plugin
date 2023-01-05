// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.
//
// Provides backwards compatibility for Spicy Zeek versions.

#pragma once

#include <zeek-spicy/autogen/config.h>

namespace spicy::compat {

// Gets the integer value of an enum.
template<typename E>
auto enum_value(E e) {
#if SPICY_VERSION_NUMBER < 10700
    return e;
#else
    return typename E::Value(e.value());
#endif
}

} // namespace spicy::compat