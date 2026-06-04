#include "attachments.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>

#include <mw/crypto.hpp>
#include <mw/error.hpp>
#include <mw/utils.hpp>

namespace unspoken
{

bool isImageMediaType(std::string_view mime)
{
    return mime.starts_with("image/");
}

std::string mediaTypeForExtension(std::string_view ext_lower)
{
    // Images (served inline).
    if(ext_lower == "png")  return "image/png";
    if(ext_lower == "jpg" || ext_lower == "jpeg") return "image/jpeg";
    if(ext_lower == "gif")  return "image/gif";
    if(ext_lower == "webp") return "image/webp";
    if(ext_lower == "svg")  return "image/svg+xml";
    if(ext_lower == "avif") return "image/avif";
    if(ext_lower == "bmp")  return "image/bmp";
    if(ext_lower == "ico")  return "image/x-icon";
    // A few common non-image types (served download-only).
    if(ext_lower == "pdf")  return "application/pdf";
    if(ext_lower == "txt")  return "text/plain";
    if(ext_lower == "mp4")  return "video/mp4";
    if(ext_lower == "webm") return "video/webm";
    if(ext_lower == "mp3")  return "audio/mpeg";
    if(ext_lower == "ogg")  return "audio/ogg";
    return "";
}

std::string extensionOf(std::string_view filename)
{
    size_t slash = filename.find_last_of("/\\");
    std::string_view base = slash == std::string_view::npos
        ? filename : filename.substr(slash + 1);
    size_t dot = base.find_last_of('.');
    if(dot == std::string_view::npos || dot + 1 >= base.size())
        return "";
    std::string ext(base.substr(dot + 1));
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return ext;
}

bool isHexLower(std::string_view s)
{
    if(s.empty()) return false;
    for(char c : s)
    {
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if(!ok) return false;
    }
    return true;
}

mw::E<StoredFile> storeAttachment(const std::string& attachment_dir,
                                  const std::string& bytes,
                                  std::string_view original_name,
                                  std::string_view declared_media_type)
{
    mw::SHA256Hasher hasher;
    ASSIGN_OR_RETURN(std::string hash, hasher.hashToHexStr(bytes));

    std::string ext = extensionOf(original_name);
    std::string media_type(declared_media_type);
    if(media_type.empty() || media_type == "application/octet-stream")
    {
        std::string derived = mediaTypeForExtension(ext);
        if(!derived.empty()) media_type = derived;
    }
    if(media_type.empty()) media_type = "application/octet-stream";

    StoredFile out;
    out.sha256 = hash;
    out.media_type = media_type;
    out.is_image = isImageMediaType(media_type);
    out.shard = hash.substr(0, 1);
    out.filename = ext.empty() ? hash : (hash + "." + ext);

    namespace fs = std::filesystem;
    fs::path dir = fs::path(attachment_dir) / out.shard;
    std::error_code ec;
    fs::create_directories(dir, ec);
    if(ec)
    {
        return std::unexpected(mw::runtimeError(std::format(
            "Failed to create attachment dir {}: {}", dir.string(),
            ec.message())));
    }
    fs::path path = dir / out.filename;
    out.disk_path = path.string();

    // Dedup: identical bytes → identical hash → same file. Only write if
    // the file does not already exist.
    if(!fs::exists(path, ec))
    {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if(!f)
        {
            return std::unexpected(mw::runtimeError(std::format(
                "Failed to open attachment file {} for writing",
                path.string())));
        }
        f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        if(!f)
        {
            return std::unexpected(mw::runtimeError(std::format(
                "Failed to write attachment file {}", path.string())));
        }
    }
    return out;
}

} // namespace unspoken
