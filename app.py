from flask import Flask, render_template, request, jsonify
from youtube_transcript_api import YouTubeTranscriptApi
from youtube_transcript_api.formatters import TextFormatter, JSONFormatter, SRTFormatter
from youtube_transcript_api.proxies import GenericProxyConfig
import re
import os
import json
import subprocess
import tempfile

app = Flask(__name__)


def extract_video_id(url_or_id):
    """Extract video ID from a YouTube URL or return the ID directly."""
    patterns = [
        r'(?:youtube\.com\/watch\?v=)([\w-]{11})',
        r'(?:youtu\.be\/)([\w-]{11})',
        r'(?:youtube\.com\/embed\/)([\w-]{11})',
        r'(?:youtube\.com\/shorts\/)([\w-]{11})',
        r'^([\w-]{11})$',
    ]
    for pattern in patterns:
        match = re.search(pattern, url_or_id.strip())
        if match:
            return match.group(1)
    return None


def get_ytt_api(proxy_url=None):
    """Create YouTubeTranscriptApi instance, optionally with proxy."""
    if proxy_url and proxy_url.strip():
        proxy_config = GenericProxyConfig(
            http_url=proxy_url.strip(),
            https_url=proxy_url.strip(),
        )
        return YouTubeTranscriptApi(proxy_config=proxy_config)
    return YouTubeTranscriptApi()


def fetch_with_ytdlp(video_id, language='en'):
    """Fallback: use yt-dlp to extract subtitles when the API is blocked."""
    url = f'https://www.youtube.com/watch?v={video_id}'
    try:
        # Try to get subtitle info first
        result = subprocess.run(
            ['yt-dlp', '--skip-download', '--write-auto-sub', '--write-sub',
             '--sub-lang', language, '--sub-format', 'json3',
             '--print-json', '--no-warnings', '-o', '-', url],
            capture_output=True, text=True, timeout=60
        )

        # Alternative approach: dump subtitles to temp dir
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, 'sub')
            subprocess.run(
                ['yt-dlp', '--skip-download', '--write-auto-sub', '--write-sub',
                 '--sub-lang', language, '--sub-format', 'json3',
                 '--no-warnings', '-o', out_path, url],
                capture_output=True, text=True, timeout=60
            )

            # Find the subtitle file
            sub_file = None
            for f in os.listdir(tmpdir):
                if f.endswith('.json3'):
                    sub_file = os.path.join(tmpdir, f)
                    break

            if not sub_file:
                # Try vtt format
                subprocess.run(
                    ['yt-dlp', '--skip-download', '--write-auto-sub', '--write-sub',
                     '--sub-lang', language, '--sub-format', 'vtt',
                     '--no-warnings', '-o', out_path, url],
                    capture_output=True, text=True, timeout=60
                )
                for f in os.listdir(tmpdir):
                    if f.endswith('.vtt'):
                        sub_file = os.path.join(tmpdir, f)
                        break

            if not sub_file:
                return None

            with open(sub_file, 'r', encoding='utf-8') as sf:
                content = sf.read()

            # Determine if it's auto-generated
            is_generated = '.auto.' in os.path.basename(sub_file) or '-auto-' in os.path.basename(sub_file)

            if sub_file.endswith('.json3'):
                data = json.loads(content)
                raw_data = []
                for event in data.get('events', []):
                    if 'segs' in event:
                        text = ''.join(seg.get('utf8', '') for seg in event['segs']).strip()
                        if text and text != '\n':
                            raw_data.append({
                                'text': text,
                                'start': event.get('tStartMs', 0) / 1000.0,
                                'duration': event.get('dDurationMs', 0) / 1000.0,
                            })
                return {
                    'raw': raw_data,
                    'language': language,
                    'language_code': language,
                    'is_generated': is_generated,
                    'method': 'yt-dlp',
                }
            else:
                # Parse VTT format
                raw_data = parse_vtt(content)
                return {
                    'raw': raw_data,
                    'language': language,
                    'language_code': language,
                    'is_generated': is_generated,
                    'method': 'yt-dlp',
                }

    except Exception:
        return None


def parse_vtt(content):
    """Parse WebVTT subtitle content into raw transcript data."""
    raw_data = []
    lines = content.strip().split('\n')
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        # Look for timestamp lines like "00:00:01.000 --> 00:00:04.000"
        time_match = re.match(r'(\d{2}:\d{2}:\d{2}\.\d{3})\s*-->\s*(\d{2}:\d{2}:\d{2}\.\d{3})', line)
        if time_match:
            start = parse_timestamp(time_match.group(1))
            end = parse_timestamp(time_match.group(2))
            duration = end - start
            i += 1
            text_lines = []
            while i < len(lines) and lines[i].strip():
                text = re.sub(r'<[^>]+>', '', lines[i].strip())  # strip HTML tags
                if text:
                    text_lines.append(text)
                i += 1
            text = ' '.join(text_lines)
            if text:
                raw_data.append({
                    'text': text,
                    'start': start,
                    'duration': duration,
                })
        else:
            i += 1
    # Deduplicate (VTT often has overlapping entries)
    seen = set()
    unique = []
    for item in raw_data:
        key = item['text']
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def parse_timestamp(ts):
    """Parse HH:MM:SS.mmm to seconds."""
    parts = ts.split(':')
    h, m = int(parts[0]), int(parts[1])
    s = float(parts[2])
    return h * 3600 + m * 60 + s


def format_raw_data(raw_data, output_format):
    """Format raw transcript data into the requested format."""
    if output_format == 'json':
        return json.dumps(raw_data, indent=2, ensure_ascii=False)
    elif output_format == 'srt':
        lines = []
        for i, item in enumerate(raw_data, 1):
            start = item['start']
            end = start + item.get('duration', 0)
            lines.append(str(i))
            lines.append(f"{srt_time(start)} --> {srt_time(end)}")
            lines.append(item['text'])
            lines.append('')
        return '\n'.join(lines)
    else:
        return '\n'.join(item['text'] for item in raw_data)


def srt_time(seconds):
    """Convert seconds to SRT timestamp format."""
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    ms = int((seconds % 1) * 1000)
    return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/transcript', methods=['POST'])
def get_transcript():
    data = request.get_json()
    video_url = data.get('video_url', '')
    language = data.get('language', 'en')
    output_format = data.get('format', 'text')
    proxy_url = data.get('proxy_url', '')
    method = data.get('method', 'auto')  # 'auto', 'api', 'ytdlp'

    video_id = extract_video_id(video_url)
    if not video_id:
        return jsonify({'error': 'Invalid YouTube URL or video ID.'}), 400

    # Method: API first, then yt-dlp fallback
    api_error = None

    if method in ('auto', 'api'):
        try:
            ytt_api = get_ytt_api(proxy_url)
            transcript = ytt_api.fetch(video_id, languages=[language])

            if output_format == 'json':
                formatter = JSONFormatter()
                formatted = formatter.format_transcript(transcript, indent=2)
            elif output_format == 'srt':
                formatter = SRTFormatter()
                formatted = formatter.format_transcript(transcript)
            else:
                formatter = TextFormatter()
                formatted = formatter.format_transcript(transcript)

            raw_data = transcript.to_raw_data()

            return jsonify({
                'success': True,
                'video_id': video_id,
                'language': transcript.language,
                'language_code': transcript.language_code,
                'is_generated': transcript.is_generated,
                'formatted': formatted,
                'raw': raw_data,
                'method': 'YouTube Transcript API',
            })

        except Exception as e:
            api_error = str(e)
            if method == 'api':
                return jsonify({'error': api_error}), 400

    # Fallback to yt-dlp
    if method in ('auto', 'ytdlp'):
        result = fetch_with_ytdlp(video_id, language)
        if result and result['raw']:
            formatted = format_raw_data(result['raw'], output_format)
            return jsonify({
                'success': True,
                'video_id': video_id,
                'language': result['language'],
                'language_code': result['language_code'],
                'is_generated': result['is_generated'],
                'formatted': formatted,
                'raw': result['raw'],
                'method': 'yt-dlp (fallback)',
            })

    error_msg = api_error or 'Could not retrieve transcript using any method.'
    return jsonify({'error': error_msg}), 400


@app.route('/languages', methods=['POST'])
def list_languages():
    data = request.get_json()
    video_url = data.get('video_url', '')
    proxy_url = data.get('proxy_url', '')

    video_id = extract_video_id(video_url)
    if not video_id:
        return jsonify({'error': 'Invalid YouTube URL or video ID.'}), 400

    try:
        ytt_api = get_ytt_api(proxy_url)
        transcript_list = ytt_api.list(video_id)

        languages = []
        for t in transcript_list:
            languages.append({
                'language': t.language,
                'language_code': t.language_code,
                'is_generated': t.is_generated,
            })

        return jsonify({'success': True, 'languages': languages})

    except Exception as e:
        return jsonify({'error': str(e)}), 400


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
