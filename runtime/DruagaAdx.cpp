// Native CRI ADX playback for The Nightmare of Druaga: Fushigi no Dungeon (SLUS-210.71).
//
// The game streams BGM through CRI ADXT -> PS2RNA -> CRI_ADXI.IRX on the IOP. That whole
// path is replaced here: the game's four ADXT calls are bound (config/druaga.toml) to these
// handlers, which decode ADX straight from BGM.AFS and play it through raylib.
//
//   druagaAdxtStartAfs  @0x615F20  ADXT_StartAfs(adxt, ptid, fid)
//   druagaAdxtStop      @0x614710  ADXT_Stop(adxt)
//   druagaAdxtGetStat   @0x6147D0  ADXT_GetStat(adxt) -> stat
//   druagaAdxtSetOutVol @0x615098  ADXT_SetOutVol(adxt, vol)   vol in 0.1 dB, 0 = full
//
// CRI's ADXM server threads never settle under the runtime's cooperative scheduler, and
// the game only uses ADXF to read DATA.DAT and to load the BGM.AFS partition. So ADXF is
// native too (synchronous reads straight from the disc files) and the two ADXM exec calls
// the game makes (0x610970, 0x610AB8) are bound to ret0.
//
//   druagaAdxfOpen            @0x60DC98  ADXF_Open(fname, atr) -> adxf
//   druagaAdxfSeek            @0x60E690  ADXF_Seek(adxf, pos_sectors, type) -> pos
//   druagaAdxfTell            @0x60E7A8  ADXF_Tell(adxf) -> pos
//   druagaAdxfReadNw          @0x60E370  ADXF_ReadNw(adxf, nsct, buf) -> nsct
//   druagaAdxfGetStat         @0x60E8F0  ADXF_GetStat(adxf) -> 3 (READEND) after a read
//   druagaAdxfLoadPartitionNw @0x60D290  ADXF_LoadPartitionNw(ptid, fname, dir, ptinfo)
//   druagaAdxfGetPtStat       @0x60D6E8  ADXF_GetPtStat(ptid) -> 3 (done)
//
// Install: copy into ps2xRuntime/src/lib/Kernel/Stubs/ and add the handler names to
// PS2_STUB_LIST in include/ps2_call_list.h (patches/0003 does both).

#include "Common.h"
#include "raylib.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <vector>

namespace ps2_stubs
{
    namespace
    {
        constexpr int kVoices = 4;
        constexpr int kFrameSamples = 32; // 18-byte block: 2 scale bytes + 16 nibble bytes
        constexpr int kBlockBytes = 18;

        enum : int32_t
        {
            ADXT_STAT_STOP = 0,
            ADXT_STAT_PLAYING = 3,
            ADXT_STAT_PLAYEND = 5,
        };

        struct AdxVoice
        {
            uint32_t adxt = 0;
            bool active = false;
            bool ended = false;
            std::vector<uint8_t> data;
            uint32_t dataStart = 0;
            int channels = 2;
            uint32_t sampleRate = 48000;
            uint32_t totalSamples = 0;
            bool loop = false;
            uint32_t loopStart = 0;
            uint32_t loopEnd = 0;
            int coef1 = 0;
            int coef2 = 0;
            uint32_t frame = 0;   // next frame to decode
            int pcmPos = kFrameSamples;
            uint32_t pcmFrame = 0; // frame currently in pcm[]
            int32_t hist[2][2] = {};
            int32_t loopHist[2][2] = {};
            bool loopHistSaved = false;
            int16_t pcm[2][kFrameSamples] = {};
            float volume = 1.0f;
            std::chrono::steady_clock::time_point started{};
        };

        std::mutex g_adxMutex;
        std::array<AdxVoice, kVoices> g_voices;
        std::array<AudioStream, kVoices> g_streams{};
        std::array<bool, kVoices> g_streamReady{};
        std::vector<std::pair<uint32_t, uint32_t>> g_afs;
        std::filesystem::path g_afsPath;
        bool g_afsLoaded = false;

        // adxt -> volume, so SetOutVol before StartAfs sticks
        std::array<std::pair<uint32_t, float>, 16> g_volumes{};

        uint16_t be16(const uint8_t *p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
        uint32_t be32(const uint8_t *p) { return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3]; }

        float volumeFor(uint32_t adxt)
        {
            for (auto &v : g_volumes)
                if (v.first == adxt)
                    return v.second;
            return 1.0f;
        }

        void setVolumeFor(uint32_t adxt, float vol)
        {
            for (auto &v : g_volumes)
                if (v.first == adxt) { v.second = vol; return; }
            for (auto &v : g_volumes)
                if (v.first == 0) { v = {adxt, vol}; return; }
        }

        bool loadAfs()
        {
            if (g_afsLoaded)
                return !g_afs.empty();
            g_afsLoaded = true;
            const PS2Runtime::IoPaths &paths = PS2Runtime::getIoPaths();
            std::filesystem::path root = !paths.cdRoot.empty() ? paths.cdRoot : paths.elfDirectory;
            if (root.empty())
                root = std::filesystem::current_path();
            for (const char *name : {"BGM.AFS", "bgm.afs", "Bgm.afs"})
            {
                std::filesystem::path p = root / name;
                if (std::filesystem::exists(p)) { g_afsPath = p; break; }
            }
            if (g_afsPath.empty())
            {
                std::cerr << "[druaga-adx] BGM.AFS not found under " << root.string() << std::endl;
                return false;
            }
            std::ifstream f(g_afsPath, std::ios::binary);
            uint8_t hdr[8];
            f.read(reinterpret_cast<char *>(hdr), 8);
            if (!f || std::memcmp(hdr, "AFS", 3) != 0)
                return false;
            uint32_t count;
            std::memcpy(&count, hdr + 4, 4);
            g_afs.resize(count);
            for (uint32_t i = 0; i < count; ++i)
            {
                uint32_t e[2];
                f.read(reinterpret_cast<char *>(e), 8);
                g_afs[i] = {e[0], e[1]};
            }
            std::cerr << "[druaga-adx] " << g_afsPath.string() << " " << count << " entries" << std::endl;
            return true;
        }

        bool parseAdx(AdxVoice &v)
        {
            const auto &d = v.data;
            if (d.size() < 0x20 || d[0] != 0x80 || d[1] != 0x00)
                return false;
            const uint16_t copyrightOffset = be16(&d[2]);
            if (d[4] != 3 || d[5] != kBlockBytes || d[6] != 4 || d[0x13] != 0)
                return false; // only plain (unencrypted) 4-bit ADX; every BGM.AFS track is this
            v.channels = std::clamp<int>(d[7], 1, 2);
            v.sampleRate = be32(&d[8]);
            v.totalSamples = be32(&d[0xC]);
            const uint16_t highpass = be16(&d[0x10]);
            const uint8_t version = d[0x12];
            v.dataStart = copyrightOffset + 4u;

            const uint32_t loopField = version == 4 ? 0x24u : 0x18u;
            v.loop = false;
            if (v.dataStart > loopField + 20u && be32(&d[loopField]) != 0)
            {
                v.loopStart = be32(&d[loopField + 4]);
                v.loopEnd = be32(&d[loopField + 12]);
                v.loop = v.loopEnd > v.loopStart && v.loopEnd <= v.totalSamples;
            }

            const double a = std::sqrt(2.0) - std::cos(2.0 * 3.14159265358979323846 * highpass / v.sampleRate);
            const double b = std::sqrt(2.0) - 1.0;
            const double c = (a - std::sqrt((a + b) * (a - b))) / b;
            v.coef1 = static_cast<int>(c * 8192.0);
            v.coef2 = static_cast<int>(c * c * -4096.0);
            return true;
        }

        // Decode v.frame into v.pcm. Returns false at the end of data.
        bool decodeFrame(AdxVoice &v)
        {
            if (v.loop && !v.loopHistSaved && v.frame == v.loopStart / kFrameSamples)
            {
                std::memcpy(v.loopHist, v.hist, sizeof(v.hist));
                v.loopHistSaved = true;
            }
            const size_t base = v.dataStart + size_t(v.frame) * kBlockBytes * v.channels;
            if (base + size_t(kBlockBytes) * v.channels > v.data.size())
                return false;
            for (int ch = 0; ch < v.channels; ++ch)
            {
                const uint8_t *blk = &v.data[base + size_t(ch) * kBlockBytes];
                const uint16_t rawScale = be16(blk);
                if (rawScale & 0x8000)
                    return false; // end-of-stream marker
                const int32_t scale = rawScale + 1;
                int32_t h1 = v.hist[ch][0], h2 = v.hist[ch][1];
                for (int i = 0; i < 16; ++i)
                {
                    const uint8_t byte = blk[2 + i];
                    for (int n = 0; n < 2; ++n)
                    {
                        int32_t nib = n == 0 ? (byte >> 4) : (byte & 0xF);
                        if (nib & 8)
                            nib -= 16;
                        int32_t s = nib * scale + ((v.coef1 * h1 + v.coef2 * h2) >> 12);
                        s = std::clamp(s, -32768, 32767);
                        h2 = h1;
                        h1 = s;
                        v.pcm[ch][i * 2 + n] = static_cast<int16_t>(s);
                    }
                }
                v.hist[ch][0] = h1;
                v.hist[ch][1] = h2;
            }
            if (v.channels == 1)
                std::memcpy(v.pcm[1], v.pcm[0], sizeof(v.pcm[0]));
            v.pcmFrame = v.frame;
            ++v.frame;
            v.pcmPos = 0;
            return true;
        }

        void restartAtLoop(AdxVoice &v)
        {
            std::memcpy(v.hist, v.loopHist, sizeof(v.hist));
            v.frame = v.loopStart / kFrameSamples;
            decodeFrame(v);
            v.pcmPos = static_cast<int>(v.loopStart % kFrameSamples);
        }

        void fill(int slot, int16_t *out, unsigned int frames)
        {
            std::lock_guard<std::mutex> lock(g_adxMutex);
            AdxVoice &v = g_voices[slot];
            for (unsigned int i = 0; i < frames; ++i)
            {
                int16_t l = 0, r = 0;
                if (v.active && !v.ended)
                {
                    if (v.pcmPos >= kFrameSamples && !decodeFrame(v))
                    {
                        if (v.loop && v.loopHistSaved) restartAtLoop(v);
                        else v.ended = true;
                    }
                    const uint32_t sampleIndex = v.pcmFrame * kFrameSamples + v.pcmPos;
                    if (!v.ended && v.loop && v.loopHistSaved && sampleIndex >= v.loopEnd)
                        restartAtLoop(v);
                    else if (!v.ended && !v.loop && sampleIndex >= v.totalSamples)
                        v.ended = true;
                    if (!v.ended)
                    {
                        l = static_cast<int16_t>(v.pcm[0][v.pcmPos] * v.volume);
                        r = static_cast<int16_t>(v.pcm[1][v.pcmPos] * v.volume);
                        ++v.pcmPos;
                    }
                }
                out[i * 2] = l;
                out[i * 2 + 1] = r;
            }
        }

        void cb0(void *b, unsigned int n) { fill(0, static_cast<int16_t *>(b), n); }
        void cb1(void *b, unsigned int n) { fill(1, static_cast<int16_t *>(b), n); }
        void cb2(void *b, unsigned int n) { fill(2, static_cast<int16_t *>(b), n); }
        void cb3(void *b, unsigned int n) { fill(3, static_cast<int16_t *>(b), n); }
        constexpr AudioCallback kCallbacks[kVoices] = {cb0, cb1, cb2, cb3};

        void ensureStream(int slot, uint32_t sampleRate)
        {
            if (!IsAudioDeviceReady() || g_streamReady[slot])
                return;
            g_streams[slot] = LoadAudioStream(sampleRate, 16, 2);
            SetAudioStreamCallback(g_streams[slot], kCallbacks[slot]);
            PlayAudioStream(g_streams[slot]);
            g_streamReady[slot] = true;
        }

        int findVoice(uint32_t adxt)
        {
            for (int i = 0; i < kVoices; ++i)
                if (g_voices[i].adxt == adxt)
                    return i;
            return -1;
        }
    }

    void druagaAdxtStartAfs(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)rdram; (void)runtime;
        const uint32_t adxt = getRegU32(ctx, 4);
        const uint32_t ptid = getRegU32(ctx, 5);
        const uint32_t fid = getRegU32(ctx, 6);
        std::cerr << "[druaga-adx] StartAfs adxt=0x" << std::hex << adxt << " ptid=" << std::dec << ptid << " fid=" << fid << std::endl;
        if (adxt == 0 || !loadAfs() || fid >= g_afs.size())
            return;

        std::vector<uint8_t> bytes(g_afs[fid].second);
        {
            std::ifstream f(g_afsPath, std::ios::binary);
            f.seekg(g_afs[fid].first);
            f.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            if (!f)
                return;
        }

        std::lock_guard<std::mutex> lock(g_adxMutex);
        int slot = findVoice(adxt);
        if (slot < 0)
            for (int i = 0; i < kVoices && slot < 0; ++i)
                if (g_voices[i].adxt == 0 || !g_voices[i].active)
                    slot = i;
        if (slot < 0)
            slot = 0;

        AdxVoice v;
        v.adxt = adxt;
        v.data = std::move(bytes);
        if (!parseAdx(v))
        {
            std::cerr << "[druaga-adx] fid " << fid << " is not plain ADX" << std::endl;
            return;
        }
        v.volume = volumeFor(adxt);
        v.active = true;
        v.started = std::chrono::steady_clock::now();
        g_voices[slot] = std::move(v);
        ensureStream(slot, g_voices[slot].sampleRate);
    }

    void druagaAdxtStop(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)rdram; (void)runtime;
        const uint32_t adxt = getRegU32(ctx, 4);
        std::lock_guard<std::mutex> lock(g_adxMutex);
        const int slot = findVoice(adxt);
        if (slot >= 0)
            g_voices[slot].active = false;
    }

    void druagaAdxtGetStat(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)rdram; (void)runtime;
        const uint32_t adxt = getRegU32(ctx, 4);
        std::lock_guard<std::mutex> lock(g_adxMutex);
        const int slot = findVoice(adxt);
        int32_t stat = ADXT_STAT_STOP;
        if (slot >= 0 && g_voices[slot].active)
        {
            AdxVoice &v = g_voices[slot];
            if (!g_streamReady[slot] && !v.loop)
            {
                // No audio device (headless): finish one-shots on wall-clock time.
                const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - v.started).count();
                if (secs * v.sampleRate >= v.totalSamples)
                    v.ended = true;
            }
            stat = v.ended ? ADXT_STAT_PLAYEND : ADXT_STAT_PLAYING;
        }
        setReturnS32(ctx, stat);
    }

    void druagaAdxtSetOutVol(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)runtime;
        const uint32_t adxt = getRegU32(ctx, 4);
        const int16_t vol = static_cast<int16_t>(getRegU32(ctx, 5) & 0xFFFF);
        if (adxt == 0)
            return;
        // ADXT_GetOutVol (0x615100, still guest code) reads adxt+0x40.
        if (uint8_t *p = getMemPtr(rdram, adxt + 0x40))
            std::memcpy(p, &vol, sizeof(vol));
        const float amp = vol <= -960 ? 0.0f : static_cast<float>(std::pow(10.0, (vol / 10.0) / 20.0));
        std::lock_guard<std::mutex> lock(g_adxMutex);
        setVolumeFor(adxt, amp);
        const int slot = findVoice(adxt);
        if (slot >= 0)
            g_voices[slot].volume = amp;
    }

    namespace
    {
        constexpr uint32_t kSector = 2048;
        constexpr uint32_t kAdxfHandleBase = 0x7ADF0000u;
        enum : int32_t { ADXF_STAT_STOP = 1, ADXF_STAT_READEND = 3, ADXF_STAT_ERROR = 4 };

        struct AdxfFile
        {
            bool open = false;
            std::filesystem::path path;
            uint64_t sizeBytes = 0;
            int32_t pos = 0; // sectors
            int32_t stat = ADXF_STAT_STOP;
        };
        std::mutex g_adxfMutex;
        std::array<AdxfFile, 8> g_adxf;

        std::string readGuestString(uint8_t *rdram, uint32_t addr)
        {
            std::string out;
            for (uint32_t i = 0; i < 256; ++i)
            {
                const uint8_t *p = getMemPtr(rdram, addr + i);
                if (!p || *p == 0)
                    break;
                out.push_back(static_cast<char>(*p));
            }
            return out;
        }

        std::filesystem::path resolveDiscFile(std::string name)
        {
            while (!name.empty() && (name[0] == '\\' || name[0] == '/'))
                name.erase(0, 1);
            if (auto semi = name.find(';'); semi != std::string::npos)
                name.resize(semi);
            const PS2Runtime::IoPaths &paths = PS2Runtime::getIoPaths();
            std::filesystem::path root = !paths.cdRoot.empty() ? paths.cdRoot : paths.elfDirectory;
            if (root.empty())
                root = std::filesystem::current_path();
            std::string upper = name, lower = name;
            for (auto &c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            for (auto &c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            for (const std::string &n : {name, upper, lower})
                if (std::filesystem::exists(root / n))
                    return root / n;
            return {};
        }

        AdxfFile *adxfFor(uint32_t handle)
        {
            const uint32_t idx = handle - kAdxfHandleBase;
            if (idx >= g_adxf.size() || !g_adxf[idx].open)
                return nullptr;
            return &g_adxf[idx];
        }
    }

    void druagaAdxfOpen(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)runtime;
        const std::string name = readGuestString(rdram, getRegU32(ctx, 4));
        const std::filesystem::path path = resolveDiscFile(name);
        std::lock_guard<std::mutex> lock(g_adxfMutex);
        if (path.empty())
        {
            std::cerr << "[druaga-adxf] open failed: " << name << std::endl;
            setReturnU32(ctx, 0);
            return;
        }
        for (size_t i = 0; i < g_adxf.size(); ++i)
        {
            if (!g_adxf[i].open)
            {
                std::error_code ec;
                g_adxf[i] = AdxfFile{true, path, std::filesystem::file_size(path, ec), 0, ADXF_STAT_STOP};
                std::cerr << "[druaga-adxf] open " << name << " -> " << path.string() << std::endl;
                setReturnU32(ctx, kAdxfHandleBase + static_cast<uint32_t>(i));
                return;
            }
        }
        setReturnU32(ctx, 0);
    }

    void druagaAdxfSeek(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)rdram; (void)runtime;
        std::lock_guard<std::mutex> lock(g_adxfMutex);
        AdxfFile *f = adxfFor(getRegU32(ctx, 4));
        if (!f) { setReturnS32(ctx, -1); return; }
        const int32_t pos = static_cast<int32_t>(getRegU32(ctx, 5));
        const int32_t type = static_cast<int32_t>(getRegU32(ctx, 6));
        const int32_t total = static_cast<int32_t>((f->sizeBytes + kSector - 1) / kSector);
        int32_t next = type == 1 ? f->pos + pos : type == 2 ? total + pos : pos;
        f->pos = std::clamp(next, 0, total);
        setReturnS32(ctx, f->pos);
    }

    void druagaAdxfTell(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)rdram; (void)runtime;
        std::lock_guard<std::mutex> lock(g_adxfMutex);
        AdxfFile *f = adxfFor(getRegU32(ctx, 4));
        setReturnS32(ctx, f ? f->pos : -1);
    }

    void druagaAdxfReadNw(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)runtime;
        std::lock_guard<std::mutex> lock(g_adxfMutex);
        AdxfFile *f = adxfFor(getRegU32(ctx, 4));
        const int32_t nsct = static_cast<int32_t>(getRegU32(ctx, 5));
        const uint32_t buf = getRegU32(ctx, 6) & 0x1FFFFFFFu;
        if (!f || nsct <= 0) { setReturnS32(ctx, 0); return; }
        uint64_t bytes = uint64_t(nsct) * kSector;
        const uint64_t offset = uint64_t(f->pos) * kSector;
        if (offset >= f->sizeBytes) { f->stat = ADXF_STAT_READEND; setReturnS32(ctx, 0); return; }
        if (buf + bytes > 0x2000000u)
            bytes = 0x2000000u - buf;
        uint8_t *dst = getMemPtr(rdram, buf);
        std::ifstream in(f->path, std::ios::binary);
        in.seekg(static_cast<std::streamoff>(offset));
        in.read(reinterpret_cast<char *>(dst), static_cast<std::streamsize>(bytes));
        const uint64_t got = static_cast<uint64_t>(in.gcount());
        const int32_t sectors = static_cast<int32_t>((got + kSector - 1) / kSector);
        f->pos += sectors;
        f->stat = ADXF_STAT_READEND;
        setReturnS32(ctx, sectors);
    }

    void druagaAdxfGetStat(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)rdram; (void)runtime;
        std::lock_guard<std::mutex> lock(g_adxfMutex);
        AdxfFile *f = adxfFor(getRegU32(ctx, 4));
        setReturnS32(ctx, f ? f->stat : ADXF_STAT_ERROR);
    }

    void druagaAdxfLoadPartitionNw(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)runtime;
        const std::string name = readGuestString(rdram, getRegU32(ctx, 5));
        std::cerr << "[druaga-adxf] partition " << getRegU32(ctx, 4) << " = " << name << " (native, BGM via StartAfs)" << std::endl;
        setReturnS32(ctx, 0);
    }

    void druagaAdxfGetPtStat(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)rdram; (void)ctx; (void)runtime;
        setReturnS32(ctx, 3); // ADXF_STAT_READEND: partition loaded
    }
}
