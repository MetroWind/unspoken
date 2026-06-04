#pragma once

// Content-addressed attachment storage (design §17). Uploaded files are
// hashed with SHA-256; the stored name is "<hash>.<ext>" under a single
// shard directory named with the first hash character. Identical bytes
// hash identically, so re-uploads dedup onto the existing file.

#include <string>
#include <string_view>

#include <mw/error.hpp>

namespace unspoken
{

struct StoredFile
{
    std::string sha256;       // lowercase hex
    std::string media_type;   // MIME type
    bool is_image = false;    // image/* (including svg) → inline
    std::string filename;     // "<hash>.<ext>"
    std::string shard;        // first hash char (the subdirectory)
    std::string disk_path;    // absolute on-disk path
};

// True for MIME types displayed inline as images (image/*, incl. SVG).
bool isImageMediaType(std::string_view mime);

// MIME type for a lowercased extension (no dot), images and a few common
// non-image types. "" means unknown → application/octet-stream upstream.
std::string mediaTypeForExtension(std::string_view ext_lower);

// Hash `bytes`, choose the stored name from `original_name`'s extension,
// and write the file under `attachment_dir/<shard>/<hash>.<ext>` unless it
// already exists (dedup). `declared_media_type` (the upload's Content-Type)
// is used when non-empty; otherwise the type is derived from the extension.
mw::E<StoredFile> storeAttachment(const std::string& attachment_dir,
                                  const std::string& bytes,
                                  std::string_view original_name,
                                  std::string_view declared_media_type);

// Lowercase extension (no dot) of a filename, or "" if none.
std::string extensionOf(std::string_view filename);

// True if `s` is a non-empty lowercase hex string (a valid hash segment).
bool isHexLower(std::string_view s);

} // namespace unspoken
