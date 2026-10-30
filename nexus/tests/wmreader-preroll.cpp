// SPDX-License-Identifier: MIT
// Integration regression: dedicated video delivery waits for audio preroll,
// with only three reusable video buffers. The reader must keep audio moving.
// Build: x86_64-w64-mingw32-g++ -O2 -static -municode wmreader-preroll.cpp -o probe.exe -lole32 -luuid
// Fixture (generated content only): ffmpeg -f lavfi -i testsrc2=size=64x48:rate=10:duration=4
//   -itsoffset 2 -f lavfi -i sine=frequency=440:sample_rate=44100:duration=2
//   -map 0:v -map 1:a -c:v wmv2 -c:a wmav2 delayed-audio.wmv
// Run in an isolated prefix with bundled ASF/WMV/WMA decoders: wine probe.exe Z:\absolute\delayed-audio.wmv
#define INITGUID
#include <cstdio>
#include <new>
#include <vector>
#include <windows.h>
#include <wmsdk.h>
static HANDLE video_slots = CreateSemaphoreW(nullptr, 3, 3, nullptr);
static HANDLE audio_seen = CreateEventW(nullptr, TRUE, FALSE, nullptr);
static LONG allocation_stalls = 0;
class Buffer final : public INSSBuffer
{
    LONG refs = 1;
    std::vector<BYTE> data;
    DWORD length;
    BOOL video;

  public:
    explicit Buffer(DWORD size, BOOL is_video) : data(size), length(size), video(is_video)
    {
    }
    ~Buffer()
    {
        if (video)
            ReleaseSemaphore(video_slots, 1, nullptr);
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **p) override
    {
        if (!p)
            return E_POINTER;
        *p = nullptr;
        if (iid != IID_IUnknown && iid != IID_INSSBuffer)
            return E_NOINTERFACE;
        *p = static_cast<INSSBuffer *>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return InterlockedIncrement(&refs);
    }
    ULONG STDMETHODCALLTYPE Release() override
    {
        LONG n = InterlockedDecrement(&refs);
        if (!n)
            delete this;
        return n;
    }
    HRESULT STDMETHODCALLTYPE GetLength(DWORD *n) override
    {
        if (!n)
            return E_POINTER;
        *n = length;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetLength(DWORD n) override
    {
        if (n > data.size())
            return E_INVALIDARG;
        length = n;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetMaxLength(DWORD *n) override
    {
        if (!n)
            return E_POINTER;
        *n = data.size();
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetBuffer(BYTE **p) override
    {
        if (!p)
            return E_POINTER;
        *p = data.data();
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetBufferAndLength(BYTE **p, DWORD *n) override
    {
        if (!p || !n)
            return E_POINTER;
        *p = data.data();
        *n = length;
        return S_OK;
    }
};
class Callback final : public IWMReaderCallback, public IWMReaderCallbackAdvanced
{
    LONG refs = 1;

  public:
    HANDLE opened = CreateEventW(nullptr, TRUE, FALSE, nullptr), done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    BOOL video_output[16] = {};
    LONG video = 0, audio = 0, nonzero = 0, allocated = 0, preroll_timeout = 0;
    HRESULT error = S_OK;
    bool block_video = true;
    DWORD start_tick = 0, second_video_ms = MAXDWORD;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **p) override
    {
        if (!p)
            return E_POINTER;
        *p = nullptr;
        if (iid == IID_IUnknown || iid == IID_IWMStatusCallback || iid == IID_IWMReaderCallback)
            *p = static_cast<IWMReaderCallback *>(this);
        else if (iid == IID_IWMReaderCallbackAdvanced)
            *p = static_cast<IWMReaderCallbackAdvanced *>(this);
        else
            return E_NOINTERFACE;
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return InterlockedIncrement(&refs);
    }
    ULONG STDMETHODCALLTYPE Release() override
    {
        return InterlockedDecrement(&refs);
    }
    HRESULT STDMETHODCALLTYPE OnStatus(WMT_STATUS status, HRESULT hr, WMT_ATTR_DATATYPE, BYTE *, void *) override
    {
        if (FAILED(hr))
        {
            error = hr;
            SetEvent(done);
        }
        if (status == WMT_OPENED)
            SetEvent(opened);
        if (status == WMT_EOF)
            SetEvent(done);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE OnSample(DWORD output, QWORD, QWORD, DWORD, INSSBuffer *sample, void *) override
    {
        BYTE *bytes = nullptr;
        DWORD size = 0;
        if (FAILED(sample->GetBufferAndLength(&bytes, &size)))
            return E_FAIL;
        if (output < 16 && video_output[output])
        {
            LONG number = InterlockedIncrement(&video);
            if (number == 2)
                second_video_ms = GetTickCount() - start_tick;
            if (number == 1 && block_video)
            {
                DWORD w = WaitForSingleObject(audio_seen, 5000);
                printf("VideoPrerollAudioWait=%lu\n", w);
                if (w != WAIT_OBJECT_0)
                    preroll_timeout = 1;
            }
            for (DWORD i = 0; i < size; i += 997)
                if (bytes[i])
                    InterlockedIncrement(&nonzero);
        }
        else
        {
            InterlockedIncrement(&audio);
            SetEvent(audio_seen);
        }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE OnStreamSample(WORD, QWORD, QWORD, DWORD, INSSBuffer *, void *) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE OnTime(QWORD, void *) override
    {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE OnStreamSelection(WORD, WORD *, WMT_STREAM_SELECTION *, void *) override
    {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE OnOutputPropsChanged(DWORD, WM_MEDIA_TYPE *, void *) override
    {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE AllocateForStream(WORD, DWORD size, INSSBuffer **p, void *) override
    {
        return AllocateForOutput(0, size, p, nullptr);
    }
    HRESULT STDMETHODCALLTYPE AllocateForOutput(DWORD output, DWORD size, INSSBuffer **p, void *) override
    {
        if (!p)
            return E_POINTER;
        *p = nullptr;
        BOOL is_video = output < 16 && video_output[output];
        if (is_video)
        {
            if (WaitForSingleObject(video_slots, 0) != WAIT_OBJECT_0)
            {
                InterlockedIncrement(&allocation_stalls);
                if (WaitForSingleObject(video_slots, 10000) != WAIT_OBJECT_0)
                    return E_OUTOFMEMORY;
            }
        }
        try
        {
            *p = new Buffer(size, is_video);
        }
        catch (...)
        {
            return E_OUTOFMEMORY;
        }
        InterlockedIncrement(&allocated);
        return S_OK;
    }
};
int wmain(int argc, wchar_t **argv)
{
    if (argc != 2 && (argc != 3 || (wcscmp(argv[2], L"--no-preroll") && wcscmp(argv[2], L"--user-clock") &&
                                    wcscmp(argv[2], L"--serial"))))
        return 2;
    setvbuf(stdout, nullptr, _IONBF, 0);
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    auto create = (HRESULT(WINAPI *)(IUnknown *, DWORD, IWMReader **))(void *)GetProcAddress(
        LoadLibraryW(L"wmvcore.dll"), "WMCreateReader");
    IWMReader *reader = nullptr;
    IWMReaderAdvanced2 *advanced = nullptr;
    Callback cb;
    bool user_clock = argc == 3 && !wcscmp(argv[2], L"--user-clock");
    bool serial = argc == 3 && !wcscmp(argv[2], L"--serial");
    cb.block_video = argc == 2 || user_clock;
    if (!create)
        return 3;
    HRESULT hr = create(nullptr, 0, &reader);
    printf("CreateAsync=%08lx\n", hr);
    if (FAILED(hr))
        return 1;
    hr = reader->Open(argv[1], &cb, nullptr);
    printf("OpenAsync=%08lx\n", hr);
    if (FAILED(hr) || WaitForSingleObject(cb.opened, 15000) != WAIT_OBJECT_0)
        return 2;
    reader->QueryInterface(IID_IWMReaderAdvanced2, (void **)&advanced);
    DWORD count = 0;
    reader->GetOutputCount(&count);
    for (DWORD output = 0; output < count && output < 16; ++output)
    {
        IWMOutputMediaProps *props = nullptr;
        DWORD size = 0;
        reader->GetOutputProps(output, &props);
        props->GetMediaType(nullptr, &size);
        std::vector<BYTE> bytes(size);
        auto type = (WM_MEDIA_TYPE *)bytes.data();
        props->GetMediaType(type, &size);
        cb.video_output[output] = type->majortype == WMMEDIATYPE_Video;
        props->Release();
        if (cb.video_output[output])
        {
            DWORD formats = 0;
            reader->GetOutputFormatCount(output, &formats);
            for (DWORD f = 0; f < formats; ++f)
            {
                reader->GetOutputFormat(output, f, &props);
                size = 0;
                props->GetMediaType(nullptr, &size);
                bytes.resize(size);
                type = (WM_MEDIA_TYPE *)bytes.data();
                props->GetMediaType(type, &size);
                if (type->subtype.Data1 == 0x3231564e)
                {
                    hr = reader->SetOutputProps(output, props);
                    printf("SetNV12=%08lx size=%lu\n", hr, type->lSampleSize);
                    props->Release();
                    break;
                }
                props->Release();
            }
        }
        if (advanced)
        {
            hr = advanced->SetAllocateForOutput(output, TRUE);
            printf("AllocateOutput%lu=%08lx\n", output, hr);
            DWORD dedicated = !serial;
            hr = advanced->SetOutputSetting(output, L"DedicatedDeliveryThread", WMT_TYPE_BOOL, (BYTE *)&dedicated,
                                            sizeof(dedicated));
            printf("Dedicated%lu=%08lx\n", output, hr);
        }
    }
    if (user_clock && advanced)
    {
        hr = advanced->SetUserProvidedClock(TRUE);
        if (FAILED(hr))
            return 3;
        hr = advanced->DeliverTime(~(QWORD)0);
        if (FAILED(hr))
            return 3;
    }
    cb.start_tick = GetTickCount();
    hr = reader->Start(0, 0, 1.0f, nullptr);
    printf("Start=%08lx\n", hr);
    DWORD waited = WaitForSingleObject(cb.done, 45000);
    HRESULT delivery_error = cb.error;
    reader->Stop();
    reader->Close();
    if (advanced)
        advanced->Release();
    reader->Release();
    printf("ASYNC waited=%lu error=%08lx video=%ld audio=%ld nonzero=%ld allocated=%ld\n", waited, delivery_error,
           cb.video, cb.audio, cb.nonzero, cb.allocated);
    CloseHandle(cb.opened);
    CloseHandle(cb.done);
    CloseHandle(video_slots);
    CloseHandle(audio_seen);
    CoUninitialize();
    printf("PREROLL timeout=%ld allocator_stalls=%ld\n", cb.preroll_timeout, allocation_stalls);
    printf("TIMING second_video_ms=%lu block_video=%u\n", cb.second_video_ms, cb.block_video);
    return (!cb.block_video && cb.second_video_ms > 1000) || cb.preroll_timeout || waited != WAIT_OBJECT_0 ||
           FAILED(delivery_error) || cb.video < 20 || cb.audio < 20 || !cb.nonzero;
}
