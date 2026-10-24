# Image and Video Analysis

## 1. Overview

Images and video are the richest form of social media evidence. A single photo can reveal location (via landmarks or EXIF), time (via shadows or weather), device (via metadata), and relationships (via who appears in the frame). For OSINT, image and video analysis is a discipline of its own: geolocation, chronolocation, verification, and reverse search.

This file covers the core techniques: extracting metadata, performing reverse image search, geolocating based on visual clues, chronolocating based on shadows and weather, and detecting manipulated media.

Relevance: social media posts frequently include images that were not intended for public scrutiny. A photo of a whiteboard, a screenshot with visible notifications, or a selfie with a reflection can reveal more than the text of the post.

## 2. Reconnaissance and Collection

Image and video collection is passive when using public posts and archives. It becomes semi-active when downloading files for analysis (still passive from the target's perspective, but the download is an action on the platform).

Key analysis dimensions:

- **Metadata.** EXIF data: camera make/model, lens, GPS coordinates, timestamp, software used, orientation.
- **Reverse search.** Google Images, Yandex, TinEye, Bing Visual Search. Yandex is often best for faces and locations in Eastern Europe and Asia.
- **Visual clues.** Landmarks, street signs, storefronts, license plates, vegetation, architectural style.
- **Time clues.** Shadows (sun position), weather, seasonal vegetation, events visible in the background.
- **People clues.** Faces (if public), clothing, badges, tattoos.

```bash
# Extract EXIF metadata from an image
exiftool image.jpg

# Extract metadata from a video (ffprobe)
ffprobe -v quiet -print_format json -show_format -show_streams video.mp4
```

Expected output (trimmed):

```text
$ exiftool image.jpg
File Name                       : image.jpg
File Size                       : 2.1 MB
Make                            : Apple
Camera Model Name               : iPhone 13 Pro
Date/Time Original              : 2025:03:15 14:32:10
GPS Latitude                    : 40 deg 44' 54.36" N
GPS Longitude                   : 73 deg 59' 8.64" W
```

The EXIF above reveals the exact GPS coordinates and timestamp. Many social platforms strip EXIF on upload, but not all; always check.

## 3. Common Attack Vectors

- **Geolocation via landmarks.** A photo with a distinctive building, sign, or landscape can be geolocated by cross-referencing with Google Maps and Street View.
- **Chronolocation via shadows.** The length and direction of shadows, combined with known location and date, can reveal the exact time. Tools like SunCalc help.
- **Reverse image search for original source.** An image posted on social media may have been taken from another source; reverse search reveals the original and any reuse.
- **Metadata leak via screenshots.** Screenshots often include EXIF and screen reflections; both can reveal information.
- **Deepfake detection.** Manipulated videos (face swaps, lip sync) can be detected by visual artifacts (lighting inconsistency, blending seams).

## 4. Exploitation Recipes

**Recipe 1 - Geolocate a photo.** Start with the largest visible landmark. Search for it on Google Maps. Then refine using street signs, storefronts, and background buildings. Confirm with Street View.

**Recipe 2 - Chronolocate a photo.** Use the position of the sun and known GPS coordinates. SunCalc shows the sun's position for any date and time. Combine with shadows and weather (visible in the photo).

**Recipe 3 - Reverse image search.** Use Yandex and Google Images. If the image is unique, search for it and check if it appears on other sites. If reused, find the original source.

**Recipe 4 - Detect deepfakes.** Look for unnatural blinking, mismatched lighting, blending seams around the face, and inconsistent shadows. Tools like Sensity AI and Deepware Scanner provide automated detection.

**Recipe 5 - Verify a video.** Extract frames with ffmpeg. Compare frames for consistency. Check the audio and video sync. Look for cuts and edits.

## 5. Post-Exploitation

- **Store evidence.** Save the original image or video, the EXIF, the reverse search results, and the geolocation analysis.
- **Build a timeline.** Combine timestamps from multiple images to reconstruct the sequence of events.
- **Map the network.** Use faces and locations to link individuals and events.
- **Document methodology.** For each conclusion, describe the steps and evidence.

## 6. Preventive Controls

- **Strip EXIF before uploading.** Most social platforms do this automatically, but not all; users should do it manually for sensitive images.
- **Be careful with screenshots.** Screenshots can include notifications, usernames, and other metadata.
- **Avoid geotagging sensitive locations.** Do not tag home, office, or sensitive facilities.
- **Train employees.** Basic awareness of what images reveal.

## 7. Detection Controls

- **Reverse image search for brand.** Check if the organization's images are being used elsewhere (impersonation).
- **Image fingerprinting.** Use perceptual hashing to detect reuploads of sensitive images.
- **Deepfake monitoring.** For executives and public figures, monitor for manipulated videos.

## 8. Verification

- **Verify the image is authentic.** Check EXIF, reverse search, and any artifacts of manipulation.
- **Verify the location.** Do not rely on a single landmark; cross-reference with at least two independent clues.
- **Verify the timestamp.** EXIF can be edited; cross-check with external clues (shadow, weather).
- **Verify the source.** If the image was reused, find the original source.

## 9. Pentest and Red Team Application

- **Phase 1 - Collect target images.** From social media and other public sources.
- **Phase 2 - Analyze for geolocation and time.** Extract clues, cross-reference with maps and SunCalc.
- **Phase 3 - Analyze for sensitive information.** Look for whiteboards, badges, screens, reflections.
- **Phase 4 - Use in pretext.** The image itself can be used in a pretext (e.g. "I saw your post at the conference; can we connect?").
- **Phase 5 - Report.** Document the exposure and the analysis process.

Red team note: image analysis is powerful but time-consuming. Focus on images that reveal the most: whiteboards, screens, badges, and location markers.

## 10. Legal and Ethical Notes

- **Public images are generally lawful to analyze.** But the content may reveal sensitive information; do not collect more than necessary.
- **Do not download or share images of individuals without consent.** Public does not mean unrestricted use.
- **Do not use image analysis for stalking or harassment.** This is a crime in many jurisdictions.
- **Respect the target's privacy.** Even if the image is public, the analysis should be limited to the engagement scope.

## 11. Production Notes

- **Use a dedicated workstation.** Do not run image analysis tools on a personal machine; use a VM or a clean environment.
- **Store original files.** Do not modify the original; work on copies.
- **Document every step.** For geolocation, describe the landmarks used and the reasoning.
- **Use automated tools where possible.** ExifTool, ffmpeg, and reverse image search APIs save time.

## 12. References

- ExifTool - https://exiftool.org/
- SunCalc - https://www.suncalc.org/
- Google Images - https://images.google.com/
- Yandex Images - https://yandex.com/images/
- TinEye - https://tineye.com/
- Bellingcat's Guide to Geolocation - https://www.bellingcat.com/resources/how-tos/2019/12/26/guide-to-the-greatest-geolocation-tools/
- Deepware Scanner - https://scanner.deepware.ai/
- Sensity AI - https://sensity.ai/