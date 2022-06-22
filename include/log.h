/*
 * Copyright (c) 2018-2021 Yubico AB. All rights reserved.
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#pragma once

// Since there is (currently) no way of logging, these functions do not do anything.
#define fido_log_debug(...) do {} while(0);
#define fido_log_xxd(...) do {} while(0);
