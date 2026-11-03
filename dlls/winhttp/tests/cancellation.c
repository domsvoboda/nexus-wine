/*
 * WinHTTP request-close cancellation regression tests.
 *
 * Copyright 2026 Nexus Maintainer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdlib.h>
#include <string.h>
#include "winsock2.h"
#include "windows.h"
#include "winhttp.h"
#include "wine/test.h"

enum operation { SEND_HEADERS, RECEIVE_HEADERS, READ_BODY, SEND_BODY };
struct fixture
{
    enum operation operation;
    SOCKET listener;
    HANDLE seen, release, done, closed;
    HINTERNET request;
    LONG closing;
    BOOL result;
    DWORD error;
};

static DWORD WINAPI serve( void *context )
{
    struct fixture *f = context;
    SOCKET client;
    char buffer[8192] = {0};
    unsigned int used = 0;
    int count;
    static const char headers[] = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n";

    if ((client = accept( f->listener, NULL, NULL )) == INVALID_SOCKET) return 1;
    while (!strstr( buffer, "\r\n\r\n" ))
    {
        count = recv( client, buffer + used, sizeof(buffer) - used - 1, 0 );
        if (count <= 0 || used + count >= sizeof(buffer) - 1)
        {
            closesocket( client );
            return 2;
        }
        used += count;
    }
    if (f->operation == READ_BODY) send( client, headers, sizeof(headers) - 1, 0 );
    SetEvent( f->seen );
    WaitForSingleObject( f->release, 10000 );
    closesocket( client );
    return 0;
}

static DWORD WINAPI perform( void *context )
{
    struct fixture *f = context;
    DWORD size = f->operation == SEND_BODY ? 32 * 1024 * 1024 : 0, read;
    DWORD total = f->operation == RECEIVE_HEADERS ? 1 : size;
    char *body = size ? calloc( 1, size ) : NULL, buffer[4];

    f->result = WinHttpSendRequest( f->request, NULL, 0, body, size, total, (DWORD_PTR)f );
    if (f->result) f->result = WinHttpReceiveResponse( f->request, NULL );
    if (f->result && f->operation == READ_BODY)
        f->result = WinHttpReadData( f->request, buffer, sizeof(buffer), &read );
    f->error = GetLastError();
    free( body );
    SetEvent( f->done );
    return 0;
}

static void CALLBACK callback( HINTERNET handle, DWORD_PTR context, DWORD status, void *info, DWORD length )
{
    struct fixture *f = (struct fixture *)context;
    if (status != WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING) return;
    InterlockedIncrement( &f->closing );
    SetEvent( f->closed );
}

static void test_cancel( enum operation operation )
{
    struct fixture f = {0};
    struct sockaddr_in address = {0};
    HANDLE server, worker;
    HINTERNET session, connection;
    int len = sizeof(address), receive_size = 1024;
    DWORD_PTR context = (DWORD_PTR)&f;
    DWORD result;
    BOOL ret;

    f.operation = operation;
    f.seen = CreateEventW( NULL, TRUE, FALSE, NULL );
    f.release = CreateEventW( NULL, TRUE, FALSE, NULL );
    f.done = CreateEventW( NULL, TRUE, FALSE, NULL );
    f.closed = CreateEventW( NULL, TRUE, FALSE, NULL );
    f.listener = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
    setsockopt( f.listener, SOL_SOCKET, SO_RCVBUF, (char *)&receive_size, sizeof(receive_size) );
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
    ret = bind( f.listener, (struct sockaddr *)&address, sizeof(address) );
    ok( !ret, "bind failed: %u\n", WSAGetLastError() );
    ret = listen( f.listener, 1 );
    ok( !ret, "listen failed: %u\n", WSAGetLastError() );
    getsockname( f.listener, (struct sockaddr *)&address, &len );
    server = CreateThread( NULL, 0, serve, &f, 0, NULL );
    session = WinHttpOpen( L"cancellation-test", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0 );
    connection = WinHttpConnect( session, L"127.0.0.1", ntohs(address.sin_port), 0 );
    f.request = WinHttpOpenRequest( connection, operation == RECEIVE_HEADERS || operation == SEND_BODY ?
                                  L"POST" : L"GET", L"/synthetic", NULL, NULL, NULL, 0 );
    ok( !!f.request, "request failed: %lu\n", GetLastError() );
    WinHttpSetOption( f.request, WINHTTP_OPTION_CONTEXT_VALUE, &context, sizeof(context) );
    WinHttpSetStatusCallback( f.request, callback, WINHTTP_CALLBACK_FLAG_HANDLES, 0 );
    worker = CreateThread( NULL, 0, perform, &f, 0, NULL );
    result = WaitForSingleObject( f.seen, 5000 );
    ok( result == WAIT_OBJECT_0, "server did not receive request: %lu\n", result );
    result = WaitForSingleObject( f.done, 100 );
    ok( result == WAIT_TIMEOUT, "operation was not held: %lu\n", result );
    ret = WinHttpCloseHandle( f.request );
    ok( ret, "close failed: %lu\n", GetLastError() );
    ret = WinHttpCloseHandle( f.request );
    ok( !ret && GetLastError() == ERROR_INVALID_HANDLE, "repeated close: %u %lu\n", ret, GetLastError() );
    result = WaitForSingleObject( f.done, 1500 );
    ok( result == WAIT_OBJECT_0, "operation did not cancel before server release: %lu\n", result );
    /* Always release the synthetic peer before teardown, including failure. */
    SetEvent( f.release );
    result = WaitForSingleObject( worker, 5000 );
    ok( result == WAIT_OBJECT_0, "worker failed to drain: %lu\n", result );
    ok( !f.result, "cancelled operation succeeded\n" );
    ok( f.error == ERROR_WINHTTP_OPERATION_CANCELLED, "expected cancellation, got %lu\n", f.error );
    result = WaitForSingleObject( f.closed, 5000 );
    ok( result == WAIT_OBJECT_0 && f.closing == 1, "closing callback: %lu %ld\n", result, f.closing );
    WinHttpCloseHandle( connection );
    WinHttpCloseHandle( session );
    WaitForSingleObject( server, 5000 );
    closesocket( f.listener );
    CloseHandle( worker );
    CloseHandle( server );
    CloseHandle( f.seen );
    CloseHandle( f.release );
    CloseHandle( f.done );
    CloseHandle( f.closed );
}

static void test_private_cancel(void)
{
    BOOL (WINAPI *abort_request)(HINTERNET);
    HINTERNET session, connection, request, other, socket;
    DWORD_PTR context = 0x1234, actual = 0;
    DWORD size = sizeof(actual);
    BOOL ret;

    abort_request = (void *)GetProcAddress( GetModuleHandleW( L"winhttp.dll" ),
                                           "__wine_winhttp_cancel_request_v1" );
    if (!abort_request)
    {
        skip( "Private Wine/XGR v1 cancellation is not available.\n" );
        return;
    }
    session = WinHttpOpen( L"private-cancel-test", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0 );
    connection = WinHttpConnect( session, L"127.0.0.1", 1, 0 );
    request = WinHttpOpenRequest( connection, L"GET", L"/never-sent", NULL, NULL, NULL, 0 );
    ret = abort_request( session );
    ok( !ret && GetLastError() == ERROR_WINHTTP_INCORRECT_HANDLE_TYPE,
        "wrong-type cancellation: %u %lu\n", ret, GetLastError() );
    ret = WinHttpSetOption( request, WINHTTP_OPTION_CONTEXT_VALUE, &context, sizeof(context) );
    ok( ret, "context option failed: %lu\n", GetLastError() );
    ret = abort_request( request );
    ok( ret, "cancel failed: %lu\n", GetLastError() );
    ret = abort_request( request );
    ok( ret, "repeated cancel failed: %lu\n", GetLastError() );
    ret = WinHttpQueryOption( request, WINHTTP_OPTION_CONTEXT_VALUE, &actual, &size );
    ok( ret && actual == context, "cancellation did not preserve handle: %u %Ix\n", ret, actual );
    other = WinHttpOpenRequest( connection, L"GET", L"/other", NULL, NULL, NULL, 0 );
    ok( !!other && other != request, "request handle was recycled\n" );
    socket = WinHttpWebSocketCompleteUpgrade( request, 0 );
    ok( !socket && GetLastError() == ERROR_WINHTTP_OPERATION_CANCELLED,
        "cancelled upgrade: %p %lu\n", socket, GetLastError() );
    ret = WinHttpSendRequest( request, NULL, 0, NULL, 0, 0, 0 );
    ok( !ret && GetLastError() == ERROR_WINHTTP_OPERATION_CANCELLED,
        "cancelled request entered transport: %u %lu\n", ret, GetLastError() );
    ret = WinHttpCloseHandle( request );
    ok( ret, "owner close failed: %lu\n", GetLastError() );
    ret = abort_request( request );
    ok( !ret && GetLastError() == ERROR_INVALID_HANDLE,
        "closed handle cancellation: %u %lu\n", ret, GetLastError() );
    WinHttpCloseHandle( other );
    WinHttpCloseHandle( connection );
    WinHttpCloseHandle( session );
}

START_TEST(cancellation)
{
    WSADATA data;
    enum operation operation;
    int ret = WSAStartup( MAKEWORD(2,2), &data );
    ok( !ret, "WSAStartup failed: %u\n", ret );
    test_private_cancel();
    for (operation = SEND_HEADERS; operation <= SEND_BODY; ++operation)
    {
        winetest_push_context( "operation %u", operation );
        test_cancel( operation );
        winetest_pop_context();
    }
    WSACleanup();
}
