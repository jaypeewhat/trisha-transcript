from flask import Flask, render_template, request, jsonify
from youtube_transcript_api import YouTubeTranscriptApi
from youtube_transcript_api.formatters import TextFormatter, JSONFormatter, SRTFormatter
import re

import os

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


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/transcript', methods=['POST'])
def get_transcript():
    data = request.get_json()
    video_url = data.get('video_url', '')
    language = data.get('language', 'en')
    output_format = data.get('format', 'text')

    video_id = extract_video_id(video_url)
    if not video_id:
        return jsonify({'error': 'Invalid YouTube URL or video ID.'}), 400

    try:
        ytt_api = YouTubeTranscriptApi()
        transcript = ytt_api.fetch(video_id, languages=[language])

        # Format based on user selection
        if output_format == 'json':
            formatter = JSONFormatter()
            formatted = formatter.format_transcript(transcript, indent=2)
        elif output_format == 'srt':
            formatter = SRTFormatter()
            formatted = formatter.format_transcript(transcript)
        else:
            formatter = TextFormatter()
            formatted = formatter.format_transcript(transcript)

        # Build raw data for the interactive view
        raw_data = transcript.to_raw_data()

        return jsonify({
            'success': True,
            'video_id': video_id,
            'language': transcript.language,
            'language_code': transcript.language_code,
            'is_generated': transcript.is_generated,
            'formatted': formatted,
            'raw': raw_data,
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/languages', methods=['POST'])
def list_languages():
    data = request.get_json()
    video_url = data.get('video_url', '')

    video_id = extract_video_id(video_url)
    if not video_id:
        return jsonify({'error': 'Invalid YouTube URL or video ID.'}), 400

    try:
        ytt_api = YouTubeTranscriptApi()
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
