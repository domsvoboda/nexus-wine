/* SPDX-License-Identifier: MIT
 * Internal native regression fixture: exercise the real dlls/gameinput/gameinput.c
 * RegisterDeviceCallback contract through a real internal game_input object.
 *
 * The production file is included verbatim (no copy, no function
 * re-implementation), so the tested body is exactly the current source.
 * Only the Win32 primitives that the included file needs are provided here.
 *
 * This is a unit-level seam: no HID device is enumerated and no controller is
 * claimed. The device list is populated directly, and the allocator failure is
 * injected through a private calloc wrapper.
 *
 * Build: x86_64-w64-mingw32-gcc -I<objdir>/include -I<srcdir>/include ...
 */

#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "initguid.h"

/* Wine headers normally provide these; keep the fixture self-contained. */
#include "devpropdef.h"
#include "devfiltertypes.h"
#include "devquery.h"
#include "hidusage.h"
#include "ddk/hidsdi.h"
#include "ddk/hidclass.h"

#include "wine/list.h"

/* ------------------------------------------------------------------------- */
/* Minimal stubs for the Win32 primitives used by the included file.          */
/* ------------------------------------------------------------------------- */

static int calloc_fail_after = -1; /* -1: never fail, 0: fail next call */
static int calloc_calls;

static void *fixture_calloc( size_t n, size_t size )
{
    if (calloc_fail_after >= 0 && calloc_calls++ >= calloc_fail_after) return NULL;
    return calloc( n, size );
}

/* Route only the included implementation allocations through the unit seam. */
#define calloc fixture_calloc

BOOLEAN WINAPI HidD_GetAttributes( HANDLE file, PHIDD_ATTRIBUTES attributes )
{ (void)file; (void)attributes; return FALSE; }
BOOLEAN WINAPI HidD_GetPreparsedData( HANDLE file, PHIDP_PREPARSED_DATA *data )
{ (void)file; (void)data; return FALSE; }
NTSTATUS WINAPI HidP_GetCaps( PHIDP_PREPARSED_DATA data, PHIDP_CAPS caps )
{ (void)data; (void)caps; return 0xc0000001; }
BOOLEAN WINAPI HidD_FreePreparsedData( PHIDP_PREPARSED_DATA data )
{ (void)data; return TRUE; }
HRESULT WINAPI DevCreateObjectQuery( DEV_OBJECT_TYPE type, ULONG flags, ULONG props_len, const DEVPROPCOMPKEY *props,
                                     ULONG filters_len, const DEVPROP_FILTER_EXPRESSION *filters,
                                     PDEV_QUERY_RESULT_CALLBACK callback, void *user_data, HDEVQUERY *devquery )
{
    (void)type; (void)flags; (void)props_len; (void)props; (void)filters_len; (void)filters; (void)callback; (void)user_data;
    *devquery = NULL;
    return E_NOTIMPL;
}
void WINAPI DevCloseObjectQuery( HDEVQUERY query ) { (void)query; }

/* ------------------------------------------------------------------------- */
/* Include the current production implementation verbatim.                    */
/* ------------------------------------------------------------------------- */

#ifndef FIXTURE_GAMEINPUT_C
#define FIXTURE_GAMEINPUT_C "../../dlls/gameinput/gameinput.c"
#endif
#include FIXTURE_GAMEINPUT_C
#undef calloc

/* ------------------------------------------------------------------------- */
/* Fixture                                                                   */
/* ------------------------------------------------------------------------- */

static int failures;
static int callback_calls;
static GameInputCallbackToken callback_token_seen;
static IGameInputDevice_v0 *callback_device_seen;

#define CHECK( cond, ... ) do { if (cond) printf( "PASS " ); else { printf( "FAIL " ); failures++; } \
                                printf( __VA_ARGS__ ); printf( "\n" ); } while (0)

static void __stdcall device_callback( GameInputCallbackToken token, void *context, IGameInputDevice_v0 *device,
                                       uint64_t timestamp, GameInputDeviceStatus current, GameInputDeviceStatus previous )
{
    (void)context; (void)timestamp; (void)current; (void)previous;
    callback_calls++;
    callback_token_seen = token;
    callback_device_seen = device;
}

static struct device *fixture_device;

static struct game_input *fixture_game_input( void )
{
    struct game_input *impl = calloc( 1, sizeof(*impl) );

    if (!impl) return NULL;
    impl->IGameInput_v0_iface.lpVtbl = &game_input_v0_vtbl;
    impl->refcount = 1;
    impl->initialized = CreateEventW( NULL, TRUE, FALSE, NULL );
    list_init( &impl->devices );
    list_init( &impl->callbacks );

    fixture_device = calloc( 1, sizeof(*fixture_device) );
    if (!impl->initialized || !fixture_device)
    {
        if (impl->initialized) CloseHandle( impl->initialized );
        free( fixture_device );
        free( impl );
        return NULL;
    }
    fixture_device->IGameInputDevice_v0_iface.lpVtbl = &game_input_device_v0_vtbl;
    fixture_device->refcount = 1;
    fixture_device->status = GameInputDeviceConnected;
    list_add_tail( &impl->devices, &fixture_device->entry );

    return impl;
}

int main( void )
{
    struct game_input *impl = fixture_game_input();
    IGameInput_v0 *game_input;
    GameInputCallbackToken token;
    HRESULT hr;

    setvbuf( stdout, NULL, _IONBF, 0 );
    if (!impl)
    {
        fprintf( stderr, "FAIL fixture setup\n" );
        return 1;
    }
    game_input = &impl->IGameInput_v0_iface;

    printf( "== 1. NULL optional callbackToken is accepted and does not fault ==\n" );
    callback_calls = 0;
    token = 0;
    hr = game_input_v0_RegisterDeviceCallback( game_input, NULL, GameInputKindGamepad, GameInputDeviceConnected,
                                               GameInputBlockingEnumeration, NULL, device_callback, NULL );
    CHECK( hr == S_OK, "NULL token registration returned %#lx", (unsigned long)hr );
    CHECK( callback_calls == 1, "blocking enumeration delivered exactly one callback, got %d", callback_calls );
    CHECK( callback_token_seen != 0, "callback received a non-zero token, got %#llx",
           (unsigned long long)callback_token_seen );
    CHECK( callback_device_seen == &fixture_device->IGameInputDevice_v0_iface,
           "callback received the enumerated device" );

    printf( "== 2. non-NULL callbackToken round-trip ==\n" );
    callback_calls = 0;
    token = 0;
    hr = game_input_v0_RegisterDeviceCallback( game_input, NULL, GameInputKindGamepad, GameInputDeviceConnected,
                                               GameInputBlockingEnumeration, NULL, device_callback, &token );
    CHECK( hr == S_OK, "non-NULL token registration returned %#lx", (unsigned long)hr );
    CHECK( token != 0, "returned token is non-zero, got %#llx", (unsigned long long)token );
    CHECK( token == callback_token_seen, "returned token equals the token passed to the callback" );
    CHECK( list_count( &impl->callbacks ) == 2, "two callbacks registered, got %d", list_count( &impl->callbacks ) );

    printf( "== 3. allocator failure returns E_OUTOFMEMORY, resets the output, registers nothing ==\n" );
    callback_calls = 0;
    token = 0xdeadbeef;
    calloc_calls = 0;
    calloc_fail_after = 0;
    hr = game_input_v0_RegisterDeviceCallback( game_input, NULL, GameInputKindGamepad, GameInputDeviceConnected,
                                               GameInputBlockingEnumeration, NULL, device_callback, &token );
    calloc_fail_after = -1;
    CHECK( hr == E_OUTOFMEMORY, "allocator failure returned %#lx", (unsigned long)hr );
    CHECK( token == 0, "token output was reset to zero, got %#llx", (unsigned long long)token );
    CHECK( callback_calls == 0, "no callback was delivered on failure, got %d", callback_calls );
    CHECK( list_count( &impl->callbacks ) == 2, "no callback entry was registered, got %d",
           list_count( &impl->callbacks ) );

    CHECK( game_input_v0_Release( game_input ) == 0, "fixture object released" );
    printf( "RESULT %s failures=%d\n", failures ? "FAIL" : "PASS", failures );
    fflush( stdout );
    return failures ? 1 : 0;
}
