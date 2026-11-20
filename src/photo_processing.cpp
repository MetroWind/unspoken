#include "photo_processing.hpp"
#include "photo_policy.hpp"

#include <Magick++.h>
#include <algorithm>
#include <list>
#include <mw/utils.hpp>
#include <optional>
#include <semaphore>

namespace unspoken
{
namespace
{
std::counting_semaphore<2> PHOTO_OPERATIONS(2);

struct PhotoOperation
{
    PhotoOperation()
    {
        PHOTO_OPERATIONS.acquire();
    }
    ~PhotoOperation()
    {
        PHOTO_OPERATIONS.release();
    }
};

mw::E<void> initialize()
{
    try
    {
        Magick::InitializeMagick(nullptr);
        auto *exception = MagickCore::AcquireExceptionInfo();
        auto installed =
            MagickCore::SetMagickSecurityPolicy(PHOTO_POLICY, exception);
        MagickCore::DestroyExceptionInfo(exception);
        if(installed == MagickCore::MagickFalse)
            return std::unexpected(
                mw::runtimeError("Cannot install photo processing policy"));
        Magick::ResourceLimits::memory(256ULL * 1024 * 1024);
        Magick::ResourceLimits::map(512ULL * 1024 * 1024);
        Magick::ResourceLimits::disk(512ULL * 1024 * 1024);
        Magick::ResourceLimits::width(16384);
        Magick::ResourceLimits::height(16384);
        Magick::ResourceLimits::listLength(128);
        Magick::ResourceLimits::thread(1);
        MagickCore::SetMagickResourceLimit(MagickCore::TimeResource, 30);
        return {};
    }
    catch(const Magick::Exception &error)
    {
        return std::unexpected(mw::runtimeError(error.what()));
    }
}

std::optional<PhotoInfo> formatInfo(const std::string &format)
{
    if(format == "JPEG") return PhotoInfo{"image/jpeg", "jpg", 0, 0};
    if(format == "PNG") return PhotoInfo{"image/png", "png", 0, 0};
    if(format == "GIF") return PhotoInfo{"image/gif", "gif", 0, 0};
    if(format == "WEBP") return PhotoInfo{"image/webp", "webp", 0, 0};
    if(format == "AVIF") return PhotoInfo{"image/avif", "avif", 0, 0};
    if(format == "JXL") return PhotoInfo{"image/jxl", "jxl", 0, 0};
    return std::nullopt;
}

mw::E<void> validateDimensions(const Magick::Image &image)
{
    const uint64_t width = image.columns();
    const uint64_t height = image.rows();
    if(!width || !height || width > 16384 || height > 16384 ||
       width > MAX_PHOTO_PIXELS / height)
        return std::unexpected(mw::HTTPError(
            400,
            "Photo exceeds the 40 megapixel or 16384 pixel dimension limit"));
    return {};
}

// Called only inside a public exception boundary with admission held.
mw::E<std::list<Magick::Image>> decodePhoto(const std::string &bytes)
{
    Magick::Blob blob(bytes.data(), bytes.size());
    Magick::Image header;
    header.quiet(false);
    header.ping(blob);
    DO_OR_RETURN(validateDimensions(header));
    if(!formatInfo(header.magick()))
        return std::unexpected(mw::HTTPError(
            400, "Photos require JPEG, PNG, GIF, WebP, AVIF or JPEG XL bytes"));
    std::list<Magick::Image> frames;
    Magick::ReadOptions options;
    options.quiet(false);
    Magick::readImages(&frames, blob, options);
    if(frames.empty())
        return std::unexpected(
            mw::HTTPError(400, "Photo contains no decoded frames"));
    for(const auto &image : frames)
        DO_OR_RETURN(validateDimensions(image));
    return frames;
}

mw::Error photoError(const Magick::Exception &error)
{
    return mw::HTTPError(
        400, std::string(
                 "Photo processing failed (check image and codec support): ") +
                 error.what());
}
} // namespace

mw::E<void> validatePhotoCompression(const PhotoCompression &settings)
{
    if(settings.format != "jpeg" && settings.format != "webp" &&
       settings.format != "avif" && settings.format != "jpegxl" &&
       settings.format != "jxl")
        return std::unexpected(mw::runtimeError(
            "photos.format must be jpeg, webp, avif or jpegxl (jxl)"));
    if(settings.quality < 1 || settings.quality > 100)
        return std::unexpected(mw::runtimeError(
            "photos.quality must be an integer between 1 and 100"));
    return {};
}

mw::E<void> initializePhotoProcessing()
{
    static const auto result = initialize();
    return result;
}

mw::E<PhotoInfo> validatePhoto(const std::string &bytes)
{
    DO_OR_RETURN(initializePhotoProcessing());
    PhotoOperation operation;
    try
    {
        ASSIGN_OR_RETURN(auto frames, decodePhoto(bytes));
        auto info = formatInfo(frames.front().magick());
        if(!info)
            return std::unexpected(mw::HTTPError(
                400, "Decoder returned an unsupported photo format"));
        info->width = frames.front().columns();
        info->height = frames.front().rows();
        return *info;
    }
    catch(const Magick::Exception &error)
    {
        return std::unexpected(photoError(error));
    }
}

mw::E<ProcessedPhoto> processPhoto(const std::string &bytes,
                                   const PhotoCompression &settings)
{
    DO_OR_RETURN(validatePhotoCompression(settings));
    DO_OR_RETURN(initializePhotoProcessing());
    PhotoOperation operation;
    try
    {
        ASSIGN_OR_RETURN(auto frames, decodePhoto(bytes));
        auto image = frames.front();
        image.autoOrient();
        image.colorSpace(Magick::sRGBColorspace);
        if(image.columns() > PHOTO_MAX_DIMENSION ||
           image.rows() > PHOTO_MAX_DIMENSION)
            image.resize(
                Magick::Geometry(PHOTO_MAX_DIMENSION, PHOTO_MAX_DIMENSION));
        image.page(Magick::Geometry(image.columns(), image.rows()));
        image.strip();
        image.depth(8);
        image.quality(settings.quality);
        std::string format;
        if(settings.format == "jpeg")
        {
            format = "JPEG";
            image.backgroundColor(Magick::Color("white"));
            image.alphaChannel(Magick::RemoveAlphaChannel);
        }
        else if(settings.format == "webp")
            format = "WEBP";
        else if(settings.format == "avif")
            format = "AVIF";
        else
            format = "JXL";
        image.magick(format);
        Magick::Blob output;
        image.write(&output);
        if(!output.length() || output.length() > MAX_PROCESSED_PHOTO_BYTES)
            return std::unexpected(mw::HTTPError(
                400, "Compressed photo exceeds the output size limit"));
        ProcessedPhoto result;
        result.bytes.assign(static_cast<const char *>(output.data()),
                            output.length());
        ASSIGN_OR_RETURN(auto encoded, decodePhoto(result.bytes));
        auto info = formatInfo(encoded.front().magick());
        if(!info || info->extension != formatInfo(format)->extension ||
           encoded.size() != 1 ||
           encoded.front().columns() > PHOTO_MAX_DIMENSION ||
           encoded.front().rows() > PHOTO_MAX_DIMENSION)
            return std::unexpected(mw::HTTPError(
                400, "Encoder returned an invalid compressed photo"));
        result.info = *info;
        result.info.width = encoded.front().columns();
        result.info.height = encoded.front().rows();
        return result;
    }
    catch(const Magick::Exception &error)
    {
        return std::unexpected(photoError(error));
    }
}
} // namespace unspoken
