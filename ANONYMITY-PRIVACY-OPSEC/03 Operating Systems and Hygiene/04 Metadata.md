# Metadata

> [!CAUTION]
> This material is provided for educational purposes, authorized security testing, and personal privacy research only. Do not use any technique or tool described here against systems, networks, or individuals without explicit written authorization. You are solely responsible for complying with all applicable laws in your jurisdiction.

Every file you create carries metadata: who made it, when, on what device, and often much more. Photos carry GPS coordinates and camera serial numbers. Office documents carry author names, revision history, and sometimes deleted text. PDFs carry software versions and creation paths. Metadata is one of the most common ways anonymity is broken.

This file is a hands-on operator guide: what metadata is, how to strip it, and how to avoid creating it in the first place.

## 1. Overview

Metadata is "data about data". For a file, metadata typically includes:

- **Timestamps:** creation, modification, access.
- **Author and owner:** user name, organization, computer name.
- **Software:** application name and version that created or edited the file.
- **Device:** camera make and model, phone IMEI (rare), printer name.
- **Location:** GPS coordinates in photos, network paths in documents.
- **Revision history:** tracked changes, comments, deleted text.
- **Thumbnails:** embedded previews that may show deleted content.
- **XMP / EXIF / IPTC:** structured metadata standards used by different applications.

Key principles:

- **Metadata is easy to leak and easy to forget.**
- **Stripping metadata is a mitigation, not a solution.** The best defense is to avoid creating metadata in the first place.
- **Every format has its own metadata quirks.** A "clean" JPG may still have EXIF; a "clean" DOCX may still have revision history.
- **Some metadata is required for the file to work.** Stripping it may break the file.

## 2. Threat Model

What metadata hygiene protects against:

- **Deanonymization via file metadata.** A leaked author name, GPS coordinate, or device serial number can identify you.
- **Correlation across documents.** The same author name or device in multiple documents links them.
- **Forensic analysis.** Investigators use metadata to establish timelines and authorship.
- **Unexpected leaks.** A photo posted on social media often contains GPS coordinates.
- **Document history leaks.** Tracked changes in a Word document can reveal internal discussions, names, or confidential information.

What metadata hygiene does NOT protect against:

- **Network-level metadata.** Who emailed whom, when, from which IP.
- **Stylometry.** Your writing style can identify you even without file metadata.
- **Behavioral correlation.** The times you are online, the sites you visit.
- **Compromised endpoint.** Malware on your device can log everything.
- **Server-side metadata.** Email providers, cloud storage, and social networks keep their own metadata about your files.
- **Cryptographic metadata.** PGP and similar tools do not hide metadata.
- **Metadata in the underlying protocol.** Even if you strip file metadata, the transport (email, HTTP) leaks its own.

Threat model summary:

| Adversary | Metadata hygiene | Without hygiene |
|-----------|------------------|-----------------|
| Content analyst (files) | Strong (if stripped) | Weak (metadata reveals identity) |
| Forensic timeline | Partial | Weak |
| Social media correlation | Strong (if stripped) | Weak (GPS, device) |
| Network-level metadata | None | None |
| Stylometry | None | None |

## 3. How It Works (technical)

**Image metadata (EXIF, IPTC, XMP):**

- **EXIF** (Exchangeable Image File Format): camera make/model, lens, exposure, GPS coordinates, timestamps, serial numbers.
- **IPTC** (International Press Telecommunications Council): captions, keywords, author.
- **XMP** (Extensible Metadata Platform): Adobe's XML-based metadata, often includes editing history.
- Photos from smartphones typically contain GPS, device model, and sometimes serial numbers.

**Document metadata (Office, PDF, ODF):**

- **Office (DOCX, XLSX, PPTX):** author, last modified by, company, revision history, tracked changes, comments, embedded thumbnails, custom XML parts.
- **PDF:** author, creator, producer, creation and modification dates, XMP, sometimes JavaScript, embedded files, and deleted-but-recoverable text.
- **ODF (ODT, ODS, ODP):** similar to Office; author, generator, editing history.
- **Markdown and plain text:** minimal metadata, but the filesystem timestamp is still there.

**Filesystem metadata:**

- Creation, modification, and access timestamps.
- File owner and group.
- Extended attributes (xattrs on Linux, ADS on NTFS).

**Container and archive metadata:**

- ZIP, TAR, and other archives preserve file metadata, including timestamps and permissions.
- Nested archives can hide metadata from naive strippers.

**Media-specific metadata:**

- **Video:** container metadata (MP4, MKV) includes creation time, device, GPS in some formats, and sometimes embedded subtitles with text.
- **Audio:** ID3 tags, recording device, and sometimes GPS in newer formats.

## 4. Installation and Setup

**Tools:**

- **`exiftool`** - the standard tool for reading and writing image metadata; also handles PDF, Office, and many other formats.
- **`mat2`** (Metadata Anonymisation Toolkit 2) - strips metadata from a wide range of formats, with a focus on images, documents, and audio/video.
- **`pdf-redact-tools`** - redacting PDFs (removes text and images, not just draws over them).
- **`qpdf`** - PDF manipulation, including metadata removal.
- **`ghostscript`** - can rewrite PDFs to remove metadata.
- **`ffmpeg`** - strip metadata from video and audio.
- **`rdfind`, `jdupes`** - not metadata tools, but useful for deduplication after stripping.
- **`tesseract`** - OCR (verify that redacted text is actually gone).

**Install (Debian/Ubuntu):**

```bash
sudo apt install libimage-exiftool-perl mat2 qpdf ghostscript ffmpeg
```

**Install (Fedora):**

```bash
sudo dnf install perl-Image-ExifTool mat2 qpdf ghostscript ffmpeg
```

**Install (Arch):**

```bash
sudo pacman -S perl-image-exiftool mat2 qpdf ghostscript ffmpeg
```

**Install (macOS):**

```bash
brew install exiftool mat2 qpdf ghostscript ffmpeg
```

**Windows:**

- ExifTool: download from https://exiftool.org/ (Perl not required in the Windows build).
- mat2: available via WSL or in a Linux VM.

## 5. Hardening and Configuration

**Hygiene from the start:**

- **Disable GPS tagging in your camera and phone.** Most phones default to GPS tagging; disable it.
- **Use a camera that does not embed serial numbers in EXIF.** Most modern cameras do; check the manual.
- **Do not use personal names in document author fields.** Set a neutral author or leave it blank.
- **Do not use templates that carry personal metadata.** A template with "John Smith" as author will put "John Smith" in every document.
- **Do not track changes in shared documents unless required.** Tracked changes are a major source of leaked information.
- **Save as PDF/A for archival.** PDF/A strips some metadata by design (but not all).
- **Print to PDF instead of Save as PDF.** Printing removes most document metadata.

**Stripping in batch:**

- **mat2:** strips metadata from many formats, with a `--inplace` option.
- **exiftool:** can strip all metadata from images and many documents.
- **qpdf:** `qpdf --linearize --replace-input file.pdf` removes some metadata; combine with `--qdf` and manual removal for full control.
- **ghostscript:** `gs -sDEVICE=pdfwrite -dCompatibilityLevel=1.4 -o out.pdf in.pdf` rewrites the PDF and drops most metadata.

**Filesystem hygiene:**

- **Set file timestamps explicitly** if they matter: `touch -t YYYYMMDDHHMM file`.
- **Do not preserve extended attributes** when copying: `cp --no-preserve=all`.
- **Strip metadata from archives** before shipping: use `zip -X` or `tar --no-xattrs`.

**Operational hygiene:**

- **Never share files you did not create without checking them first.**
- **Re-strip after every edit.** Editing a stripped file may reintroduce metadata (e.g. Word adds last-modified-by).
- **Use a dedicated "clean" machine for producing files that will be published.**
- **Test the result.** Use `exiftool` or `mat2 --show` to verify the file is clean.

## 6. Operational Usage

**Read metadata:**

```bash
exiftool file.jpg
mat2 --show file.jpg
```

**Strip metadata from images:**

```bash
mat2 --inplace file.jpg
# Or:
exiftool -all= file.jpg
```

**Strip metadata from PDFs:**

```bash
mat2 --inplace file.pdf
# Or:
qpdf --linearize --replace-input file.pdf
# For a more thorough rewrite:
gs -sDEVICE=pdfwrite -dCompatibilityLevel=1.4 -dPDFSETTINGS=/prepress -dNOPAUSE -dQUIET -dBATCH -sOutputFile=out.pdf in.pdf
```

**Strip metadata from Office documents (DOCX, XLSX, PPTX):**

- **Word:** use "Inspect Document" (File -> Info -> Check for Issues -> Inspect Document). Remove all metadata, comments, and tracked changes.
- **LibreOffice:** Tools -> "Remove personal information on saving" (in Options). Or "File -> Properties" to clear fields.
- **Best practice:** convert to PDF, then strip the PDF.

**Strip metadata from video:**

```bash
ffmpeg -i input.mp4 -map_metadata -1 -c copy output.mp4
```

**Strip metadata from audio:**

```bash
ffmpeg -i input.mp3 -map_metadata -1 -c copy output.mp3
```

**Verify a file is clean:**

```bash
exiftool file.jpg | grep -iE "gps|author|serial|software|device"
mat2 --show file.jpg
```

**Redact text in a PDF (properly):**

- Do not just draw a black box over the text; the text is still there.
- Use `pdf-redact-tools` or a PDF editor that actually removes the text.
- Verify by running OCR (`tesseract`) on the redacted area; the text should not appear.

```bash
# Convert PDF to images, redact visually, then OCR to verify
pdftoppm -png file.pdf page
# Edit page-1.png to black out sensitive text
# Then create a new PDF from the images:
img2pdf page-1.png -o file-redacted.pdf
```

**Timestamps:**

```bash
# Set specific timestamps
touch -t 202001010000 file.txt

# Copy with no preserved metadata
cp --no-preserve=all source.txt dest.txt
```

## 7. Common Mistakes

Real mistakes that break metadata hygiene:

1. **Posting a photo without stripping GPS.** The single most common metadata leak.
2. **Assuming "Save as PDF" strips metadata.** It often preserves author and creator.
3. **Using "Print to PDF" but then editing the PDF.** Editing reintroduces metadata.
4. **Stripping once and never again.** Editing a file reintroduces metadata.
5. **Using Word's "Track Changes" on a document that will be shared.** Reveals internal discussions.
6. **Leaving comments in Office documents.** Comments are metadata.
7. **Using a template with a personal author name.** Every new document inherits it.
8. **Assuming ZIP strips metadata.** ZIP preserves file metadata.
9. **Forgetting that nested archives can hide metadata.** A "clean" outer archive can contain a dirty inner one.
10. **Redacting a PDF by drawing a black box.** The text is still there.
11. **Assuming EXIF is the only metadata.** IPTC, XMP, and container metadata also exist.
12. **Using a public "metadata remover" website.** You do not know what they do with your file.
13. **Assuming cloud storage strips metadata.** Most providers preserve it.
14. **Forgetting filesystem timestamps.** They are metadata too.
15. **Forgetting that OCR can recover text under black boxes.**

## 8. Attacks Against It

Known attacks and limitations:

- **Metadata recovery.** Even after stripping, some formats retain metadata in non-obvious places (e.g. Office XML parts, PDF XMP, EXIF thumbnails).
- **Thumbnail recovery.** EXIF thumbnails may contain a smaller version of the original image, which can be enlarged and analyzed.
- **Deleted text recovery in Office documents.** DOCX files are ZIP archives; the `document.xml` may contain deleted-but-retained text.
- **PDF incremental updates.** A PDF that is "redacted" by an overlay may still contain the original text in the incremental update.
- **OCR of black-box redactions.** A black box over text does not remove the text; OCR recovers it.
- **Stylometry.** Even with no metadata, writing style can identify the author.
- **Behavioral correlation.** The times you publish files, the sites you visit.
- **Metadata in the transport layer.** Even if the file is clean, the email headers, HTTP requests, and DNS queries are not.
- **Watermarking.** Some software embeds invisible watermarks in the content itself.
- **Content-based fingerprinting.** The file content itself can be matched to a known source.
- **Cross-file correlation.** Multiple files with the same neutral author still correlate if published together.

## 9. Detection (Blue Team)

What a forensic analyst or defender can see:

- **Metadata extraction.** Tools like `exiftool`, `mat2 --show`, and `pdfinfo` reveal what metadata remains.
- **Thumbnail recovery.** ExifTool can extract embedded thumbnails.
- **Office XML inspection.** Unzip a DOCX and inspect `docProps/` and `word/document.xml`.
- **PDF incremental update analysis.** Tools like `qpdf --qdf` and `mutool` reveal incremental updates and hidden objects.
- **OCR of images.** Tesseract can recover text that was visually redacted.
- **Stylometry.** Forensic linguists can attribute authorship by writing style.
- **Timeline analysis.** Filesystem and document timestamps establish timelines.
- **Cross-file correlation.** Matching neutral metadata across documents links them to the same author or workflow.
- **Watermark analysis.** Some watermarks are designed to be detectable even after processing.

## 10. Case Studies

- **The "Pentagon Papers" and metadata (1971, pre-digital).** The original leak was traced through physical copying patterns. The digital equivalent is metadata.
- **The "Cat in the Hat" and FBI (2014).** A user was identified through a combination of metadata and operational mistakes.
- **Vice and the "photobomb" metadata leak (2014).** A Vice article about a hacker was published with a photo that contained GPS coordinates, revealing the hacker's location.
- **John McAfee and EXIF GPS (2012).** A photo posted by McAfee's team contained EXIF GPS coordinates, revealing his location in Guatemala.
- **Microsoft Office document leaks (multiple, 2010s).** Governments and companies have leaked sensitive information through tracked changes and comments left in DOCX files.
- **Redacted PDF leaks (multiple).** Redactions that were drawn as black boxes were reversed by OCR, revealing the underlying text (e.g. in court filings).
- **Edward Snowden and metadata (2013).** Snowden was careful about metadata; his leaks and subsequent communications are a case study in operational discipline.
- **Aidan Dodson and metadata (2022).** A Twitter account was linked to a person through metadata in posted images.

(These are documented public events; no new attacks are disclosed here.)

## 11. Legal and Ethical Notes

Metadata stripping is legal for files you own. However:

- **Do not strip metadata from files you do not own or have authority over.** Removing attribution from a copyrighted work may violate copyright law.
- **Do not use metadata stripping to evade legal obligations.** If you are under a legal hold, do not strip metadata from relevant files.
- **Corporate data.** Stripping metadata from corporate files may violate company policy.
- **Evidence.** If you suspect a file is evidence in a crime, do not modify it; contact law enforcement.
- **Attribution.** Removing author metadata from a document may violate attribution requirements (e.g. Creative Commons licenses).
- **Authorized use only.** In a professional context, use metadata stripping only within the scope of an authorized engagement or on your own files.

## 12. Production Notes

If you are deploying metadata hygiene for a small group:

- **Standardize the toolchain.** mat2 + exiftool for most formats; qpdf/ghostscript for PDFs.
- **Define a pre-publish checklist.** Every file that leaves the group must pass metadata inspection.
- **Automate where possible.** A shell script that runs `mat2 --inplace` on all files in a directory is easy and prevents mistakes.
- **Cover all formats.** Images, documents, PDFs, video, audio, archives.
- **Cover filesystem timestamps.** `touch -t` and `cp --no-preserve=all`.
- **Train users.** Metadata leaks are common even among experienced users.
- **Test the procedure.** Verify with `exiftool` and `mat2 --show` on a test file.
- **Re-strip after every edit.** Editing reintroduces metadata.
- **Monitor the threat model.** File formats evolve; new metadata fields appear. Re-evaluate periodically.

## 13. References

- ExifTool - https://exiftool.org/
- mat2 (Metadata Anonymisation Toolkit 2) - https://0xacab.org/jvoisin/mat2
- qpdf - https://qpdf.readthedocs.io/
- Ghostscript - https://www.ghostscript.com/
- ffmpeg - https://ffmpeg.org/
- Tesseract OCR - https://github.com/tesseract-ocr/tesseract
- Electronic Frontier Foundation - Surveillance Self-Defense - https://ssd.eff.org/
- Privacy Guides - File Metadata - https://www.privacyguides.org/en/metadata/
- NIST SP 800-101 Rev. 1: Guidelines on Mobile Device Forensics - https://csrc.nist.gov/publications/detail/sp/800-101/rev-1/final
