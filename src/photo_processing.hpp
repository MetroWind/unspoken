#pragma once

#include <cstdint>
#include <mw/error.hpp>
#include <string>

namespace unspoken
{
// Encoding settings for new photo uploads and offline photo imports.
struct PhotoCompression
{
    std::string format = "webp";
    int quality = 85;
};

// Check the format allowlist and the inclusive 1..100 quality range.
mw::E<void> validatePhotoCompression(const PhotoCompression &settings);

// Bounded decoded raster metadata; no ImageMagick objects escape the wrapper.
struct PhotoInfo
{
    std::string media_type;
    std::string extension;
    uint64_t width = 0;
    uint64_t height = 0;
};

// Compressed canonical photo bytes and their detected metadata.
struct ProcessedPhoto
{
    std::string bytes;
    PhotoInfo info;
};

// Maximum input pixels per frame, checked before and after full decoding.
inline constexpr uint64_t MAX_PHOTO_PIXELS = 40000000;
// Canonical photo dimensions fit inside this square without upscaling.
inline constexpr uint64_t PHOTO_MAX_DIMENSION = 1024;
// Bound encoded output independently of the original-upload byte limit.
inline constexpr uint64_t MAX_PROCESSED_PHOTO_BYTES = 32 * 1024 * 1024;

// Install the process policy once, before starting application workers.
mw::E<void> initializePhotoProcessing();

// Fully decode supported raster bytes, rejecting warnings and resource errors.
// At most two validation/processing callers run concurrently.
mw::E<PhotoInfo> validatePhoto(const std::string &bytes);

// Orient, fit within 1024x1024, convert to sRGB, strip metadata, and encode
// the first frame. JPEG composites transparency on white. No files are saved.
mw::E<ProcessedPhoto> processPhoto(const std::string &bytes,
                                   const PhotoCompression &settings);
} // namespace unspoken
