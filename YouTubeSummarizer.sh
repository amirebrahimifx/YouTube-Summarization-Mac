#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title YouTube → Transcript → Groq(OpenRouter) (No-Thinking Prompt)
# @raycast.mode fullOutput
# @raycast.packageName YouTube AI
# @raycast.icon ▶️
# @raycast.argument1 { "type": "text", "placeholder": "Question (optional; empty = summarize)", "optional": true }
# @raycast.needsConfirmation false

set -euo pipefail

# =============================================================================
# CONFIG
# =============================================================================
MODEL="openai/gpt-oss-120b"
OPENROUTER_ENDPOINT="https://openrouter.ai/api/v1/chat/completions"
APIFY_ENDPOINT="https://api.apify.com/v2/acts/supreme_coder~youtube-transcript-scraper/run-sync-get-dataset-items"

# Prefer Groq via OpenRouter (fast + cheap), but allow fallback if Groq is unavailable.
PROVIDER_JSON='{"order":["groq"],"allow_fallbacks":true,"sort":"throughput"}'

# Output / cost controls
TEMPERATURE="0.2"
MAX_TOKENS="900"
MAX_TRANSCRIPT_CHARS=200000

# Debug temp files (curl_debug)
HDR_FILE="/tmp/raycast_ytai_headers.txt"
BODY_FILE="/tmp/raycast_ytai_body.txt"

# =============================================================================
# UTILITIES
# =============================================================================
hr() { echo "----------------------------------------"; }
die() { echo "Error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }
trim_crlf() { printf "%s" "$1" | tr -d '\r\n'; }

# Detect hex-only strings
is_hex() {
  local s="$1"
  [[ -n "$s" && "$s" =~ ^[0-9a-fA-F]+$ ]]
}

# Decode hex -> ASCII (best effort)
hex_to_ascii() {
  local hex="$1"
  python3 - <<'PY' "$hex" 2>/dev/null || true
import sys, binascii
h=sys.argv[1].strip()
try:
    b=binascii.unhexlify(h)
    print(b.decode("utf-8", errors="strict"))
except Exception:
    print("")
PY
}

# Normalize OpenRouter API key:
# - trims
# - if it looks like hex and starts with 736b ("sk"), decode it
# - trims again
normalize_openrouter_key() {
  local k
  k="$(trim_crlf "$1")"

  if is_hex "$k" && [[ $(( ${#k} % 2 )) -eq 0 ]]; then
    if [[ "${k:0:4,,}" == "736b" ]]; then
      local decoded
      decoded="$(hex_to_ascii "$k")"
      if [[ -n "$decoded" ]]; then
        k="$(trim_crlf "$decoded")"
      fi
    fi
  fi

  printf "%s" "$k"
}

# curl wrapper that preserves error bodies (no -f)
curl_debug() {
  local label="$1"; shift

  : >"$HDR_FILE"
  : >"$BODY_FILE"

  local status
  status="$(curl -sS -D "$HDR_FILE" -o "$BODY_FILE" -w "%{http_code}" "$@" || true)"

  if [[ -z "${status}" ]]; then
    die "$label: curl failed (no HTTP status received)."
  fi

  if [[ "$status" =~ ^2[0-9][0-9]$ ]]; then
    cat "$BODY_FILE"
    return 0
  fi

  echo "$label: HTTP $status" >&2
  hr >&2
  echo "Response headers (first 30 lines):" >&2
  sed -n '1,30p' "$HDR_FILE" >&2 || true
  hr >&2
  echo "Response body:" >&2
  if command -v jq >/dev/null 2>&1 && jq -e . >/dev/null 2>&1 <"$BODY_FILE"; then
    cat "$BODY_FILE" | jq . >&2
  else
    sed -n '1,220p' "$BODY_FILE" >&2 || true
  fi
  hr >&2

  return 1
}

not_youtube_exit() {
  echo "Clipboard does not contain a YouTube URL. Nothing to do."
  exit 0
}

# =============================================================================
# YOUTUBE HELPERS (Python)
# =============================================================================
extract_video_id() {
  local u="$1"
  python3 - <<'PY' "$u" 2>/dev/null || true
import re, sys, urllib.parse
u=sys.argv[1].strip()
try:
    p=urllib.parse.urlparse(u)
except Exception:
    print(""); raise SystemExit

host=(p.netloc or "").lower()
path=p.path or ""
qs=urllib.parse.parse_qs(p.query or "")

vid=""

if "youtu.be" in host:
    m=re.match(r"^/([A-Za-z0-9_-]{6,})", path)
    if m: vid=m.group(1)

if not vid and ("youtube.com" in host or "youtube-nocookie.com" in host):
    if path.startswith("/watch"):
        v=qs.get("v", [""])[0]
        if v: vid=v
    if not vid:
        m=re.match(r"^/shorts/([A-Za-z0-9_-]{6,})", path)
        if m: vid=m.group(1)
    if not vid:
        m=re.match(r"^/embed/([A-Za-z0-9_-]{6,})", path)
        if m: vid=m.group(1)

vid=(vid.split("&")[0]).strip()
print(vid)
PY
}

choose_caption_track() {
  local xml="$1"
  python3 - <<'PY' "$xml" 2>/dev/null || true
import sys, xml.etree.ElementTree as ET, json
xml_text=sys.argv[1]
try:
    root=ET.fromstring(xml_text)
except Exception:
    print(""); raise SystemExit

tracks=[]
for t in root.findall("track"):
    tracks.append({
        "lang": (t.attrib.get("lang_code","") or "").strip(),
        "kind": (t.attrib.get("kind","") or "").strip(),  # "asr" => auto
    })
if not tracks:
    print(""); raise SystemExit

autos=[x for x in tracks if x["kind"]=="asr" and x["lang"]]
manuals=[x for x in tracks if x["kind"]!="asr" and x["lang"]]

def pick():
    # If auto exists, assume its language == spoken language.
    # Prefer manual same language; else auto.
    if autos:
        spoken=autos[0]["lang"]
        if any(m["lang"]==spoken for m in manuals):
            return {"lang": spoken, "asr": False}
        return {"lang": spoken, "asr": True}

    # No autos: prefer English manual; else first manual; else first auto
    if any(m["lang"]=="en" for m in manuals):
        return {"lang":"en","asr":False}
    if manuals:
        return {"lang": manuals[0]["lang"], "asr": False}
    if autos:
        return {"lang": autos[0]["lang"], "asr": True}
    return {"lang": tracks[0]["lang"] or "en", "asr": False}

print(json.dumps(pick()))
PY
}

vtt_to_text() {
  local vtt="$1"
  python3 - <<'PY' "$vtt" 2>/dev/null || true
import sys, re
vtt=sys.argv[1]
out=[]
for line in vtt.splitlines():
    s=line.strip()
    if not s: 
        continue
    if s.startswith("WEBVTT"):
        continue
    if "-->" in s:
        continue
    if re.fullmatch(r"\d+", s):
        continue
    s=re.sub(r"<[^>]+>", "", s)
    out.append(s)
text=" ".join(out)
text=re.sub(r"\s+", " ", text).strip()
print(text)
PY
}

urlencode() {
  python3 - <<'PY' "$1"
import sys, urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=""))
PY
}

# =============================================================================
# START
# =============================================================================
need curl
need jq
need python3

QUESTION="${1:-}"

URL_RAW="$(pbpaste | tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
[[ -n "$URL_RAW" ]] || not_youtube_exit

VID="$(extract_video_id "$URL_RAW")"
[[ -n "$VID" ]] || not_youtube_exit

YOUTUBE_URL="$URL_RAW"

echo "YouTube video ID: $VID"
echo "URL: $YOUTUBE_URL"
hr

# =============================================================================
# FETCH TITLE (oEmbed) - fast and no API key
# =============================================================================
ENC_URL="$(urlencode "$YOUTUBE_URL")"
TITLE="$(curl -sS "https://www.youtube.com/oembed?url=${ENC_URL}&format=json" \
  | jq -r '.title // empty' 2>/dev/null || true)"
[[ -n "$TITLE" ]] || TITLE="(title unavailable)"

echo "Title: $TITLE"
hr

# =============================================================================
# LOAD SECRETS (Keychain)
# =============================================================================
OPENROUTER_API_KEY_RAW="$(security find-generic-password -a "$USER" -s "openrouter_api_key" -w 2>/dev/null || true)"
APIFY_TOKEN_RAW="$(security find-generic-password -a "$USER" -s "apify_token" -w 2>/dev/null || true)"

OPENROUTER_API_KEY="$(normalize_openrouter_key "$OPENROUTER_API_KEY_RAW")"
APIFY_TOKEN="$(trim_crlf "$APIFY_TOKEN_RAW")"

# Validate OpenRouter key
if [[ -z "${OPENROUTER_API_KEY}" || "${#OPENROUTER_API_KEY}" -lt 20 ]]; then
  die "OpenRouter API key missing/too short inside Raycast (len=${#OPENROUTER_API_KEY})."
fi
if [[ "${OPENROUTER_API_KEY}" != sk-* ]]; then
  die "OpenRouter key does not look like an API key (expected to start with 'sk-'). Re-copy your OpenRouter API key and re-save it in Keychain."
fi

# Diagnostic (safe-ish)
echo "OpenRouter key length: ${#OPENROUTER_API_KEY}"
echo "OpenRouter key prefix: ${OPENROUTER_API_KEY:0:10}****"
hr

USE_APIFY=1
if [[ -z "${APIFY_TOKEN}" || "${#APIFY_TOKEN}" -lt 10 ]]; then
  USE_APIFY=0
  echo "Note: Apify token not found (service: apify_token). Apify fallback is disabled."
  hr
fi

# =============================================================================
# PHASE A: Direct YouTube captions (free)
# =============================================================================
TRANSCRIPT_TEXT=""
CAPTION_LANG=""
CAPTION_AUTO=""

echo "Phase A: Attempting direct YouTube captions..."
TRACKS_XML="$(curl -sS "https://www.youtube.com/api/timedtext?type=list&v=${VID}" || true)"

if [[ -n "$TRACKS_XML" ]]; then
  CHOSEN="$(choose_caption_track "$TRACKS_XML")"
  if [[ -n "$CHOSEN" ]]; then
    CAPTION_LANG="$(echo "$CHOSEN" | jq -r '.lang // empty')"
    IS_ASR="$(echo "$CHOSEN" | jq -r '.asr // false')"

    if [[ -n "$CAPTION_LANG" ]]; then
      if [[ "$IS_ASR" == "true" ]]; then
        CAPTION_AUTO="true"
        VTT="$(curl -sS "https://www.youtube.com/api/timedtext?v=${VID}&lang=${CAPTION_LANG}&kind=asr&fmt=vtt" || true)"
      else
        CAPTION_AUTO="false"
        VTT="$(curl -sS "https://www.youtube.com/api/timedtext?v=${VID}&lang=${CAPTION_LANG}&fmt=vtt" || true)"
      fi

      if [[ -n "${VTT:-}" ]]; then
        TRANSCRIPT_TEXT="$(vtt_to_text "$VTT")"
      fi
    fi
  fi
fi

if [[ -n "$TRANSCRIPT_TEXT" ]]; then
  echo "Direct captions OK: lang=${CAPTION_LANG} auto=${CAPTION_AUTO}"
else
  echo "Direct captions not available or failed."
fi

hr
# =============================================================================
# PHASE B: Apify fallback (paid)
# =============================================================================
APIFY_META=""
if [[ -z "$TRANSCRIPT_TEXT" ]]; then
  if [[ "$USE_APIFY" -ne 1 ]]; then
    die "No transcript via direct captions, and Apify fallback is disabled (missing apify_token)."
  fi

  echo "Phase B: Falling back to Apify transcript actor..."

  # Prefer Persian if the YouTube title contains Persian/Arabic script; else English.
  # (This matters when Phase A fails and we otherwise default to English.)
  IS_FA="$(python3 - <<'PY' "$TITLE"
import sys, re
t=sys.argv[1]
print("1" if re.search(r"[\u0600-\u06FF]", t) else "0")
PY
)"
  if [[ "$IS_FA" == "1" ]]; then
    LANGS_JSON='["fa","en"]'
  else
    LANGS_JSON='["en"]'
  fi

  APIFY_PAYLOAD="$(jq -nc --arg url "$YOUTUBE_URL" --argjson langs "$LANGS_JSON" \
    '{urls:[{url:$url}], languages:$langs, outputFormat:"json"}')"

  APIFY_RESP="$(curl_debug "Apify" \
    -X POST "$APIFY_ENDPOINT" \
    -H "Authorization: Bearer ${APIFY_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "$APIFY_PAYLOAD" \
  )" || die "Apify call failed (see details above)."

  # ---- Debug: show what Apify actually returned (summary only) ----
  ITEM_COUNT="$(echo "$APIFY_RESP" | jq -r 'length' 2>/dev/null || echo "0")"
  echo "Apify items returned: $ITEM_COUNT"
  echo "Apify languages requested: $LANGS_JSON"

  if [[ "$ITEM_COUNT" == "0" ]]; then
    hr
    echo "Apify returned an empty array. Raw response:" >&2
    echo "$APIFY_RESP" | (jq . 2>/dev/null || cat) >&2
    hr
    die "Apify returned 0 items (likely no subtitles available or actor could not access the video)."
  fi

  # ---- Robust transcript extraction (handles array-of-chunks OR string transcript) ----
  TRANSCRIPT_TEXT="$(echo "$APIFY_RESP" | jq -r '
    def join_chunks(x):
      if (x|type)=="array" then (x|map(.text // .caption // .value // "")|join(" "))
      elif (x|type)=="string" then x
      else "" end;

    (.[0] // {}) as $item
    | (
        join_chunks($item.transcript)
        // $item.transcriptText
        // $item.text
        // $item.captionsText
        // ""
      )
  ' 2>/dev/null || true)"

  APIFY_LANG_CODE="$(echo "$APIFY_RESP" | jq -r '.[0].languageCode // empty' 2>/dev/null || true)"
  APIFY_IS_GEN="$(echo "$APIFY_RESP" | jq -r '.[0].isGenerated // empty' 2>/dev/null || true)"
  APIFY_META="Apify(lang=${APIFY_LANG_CODE:-?}, auto=${APIFY_IS_GEN:-?})"

  # ---- If still empty, print a structured preview to diagnose schema / errors ----
  if [[ -z "$TRANSCRIPT_TEXT" ]]; then
    hr
    echo "Apify returned an item but transcript extraction was empty." >&2
    echo "First item keys:" >&2
    echo "$APIFY_RESP" | jq -r '.[0] | keys' >&2 || true
    hr >&2
    echo "First item preview (redacted-ish):" >&2
    echo "$APIFY_RESP" | jq '.[0] | {
      url: (.url // .videoUrl // .inputUrl // null),
      title: (.title // null),
      languageCode: (.languageCode // null),
      isGenerated: (.isGenerated // null),
      transcriptType: (.transcript|type?),
      transcriptLen: (if (.transcript|type?)=="array" then (.transcript|length) elif (.transcript|type?)=="string" then (.transcript|length) else null end),
      error: (.error // .errors // .message // null)
    }' >&2 || true
    hr >&2

    die "Apify returned a response but transcript text was empty (see preview above)."
  fi

  echo "Apify transcript OK: $APIFY_META"
  hr
fi
# =============================================================================
# PHASE C: OpenRouter (Groq-first) summary/Q&A, minimal reasoning
# =============================================================================
echo "Phase C: Calling OpenRouter model: $MODEL (Groq-first, low reasoning)..."

if [[ -n "$QUESTION" ]]; then
  TASK="Answer this question using only the transcript:\n${QUESTION}"
else
  TASK="Summarize the video using only the transcript."
fi

# New prompt: story + title-question answer + key points + 10-part timeline
OR_PAYLOAD="$(jq -nc \
  --arg model "$MODEL" \
  --arg url "$YOUTUBE_URL" \
  --arg title "$TITLE" \
  --arg task "$TASK" \
  --arg transcript "$TRANSCRIPT_TEXT" \
  --argjson provider "$PROVIDER_JSON" \
  --argjson temperature "$TEMPERATURE" \
  --argjson max_tokens "$MAX_TOKENS" \
  '{
    model: $model,
    temperature: $temperature,
    max_tokens: $max_tokens,

    # Ask for minimal/no reasoning where supported
    reasoning: { effort: "low" },

    # Provider routing (Groq first)
    provider: $provider,

    messages: [
      {
        role: "system",
        content: "Follow instructions exactly. Do not provide chain-of-thought or analysis. Use only the transcript."
      },
      {
        role: "user",
        content:
          ("YouTube URL: " + $url + "\n" +
           "Video title: " + $title + "\n\n" +
           $task + "\n\n" +
           "Output rules:\n" +
           "- No hidden reasoning. Do not include chain-of-thought or analysis.\n" +
           "- Be fast and direct. Prefer short sentences.\n" +
           "- Use ONLY the transcript. If something is uncertain, say \"Unknown from transcript.\"\n\n" +
           "Produce exactly:\n\n" +
           "Paragraph 1 (Story):\n" +
           "A compact narrative of what happens in the video (4–8 sentences). Mention the main topic, what changes, and the conclusion.\n\n" +
           "Paragraph 2 (Title Question Answer):\n" +
           "Use the provided video title. If the title is a question (ends with '?' or is phrased as a question), answer it in 3–6 sentences using only transcript evidence.\n" +
           "If the title is not a question, infer the most likely question the title implies and answer that.\n\n" +
           "Paragraph 3 (Key Points):\n" +
           "5–10 bullets, each a concrete claim or takeaway from the transcript (not generic).\n\n" +
           "Timeline (10 segments):\n" +
           "Create 10 numbered items: 1/10 … 10/10.\n" +
           "Each item: 1–2 sentences describing what is discussed in that portion of the video.\n" +
           "If timing is not available, approximate by progression through the transcript (early → late).\n\n" +
           "Finally:\n" +
           "\"Best quote:\" one short phrase (max 20 words) copied verbatim from the transcript if available; otherwise \"None\".\n\n" +
           "Transcript:\n" + $transcript)
      }
    ]
  }'
)"

OR_RESP="$(curl_debug "OpenRouter" \
  -X POST "$OPENROUTER_ENDPOINT" \
  -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
  -H "Content-Type: application/json" \
  -H "HTTP-Referer: https://raycast.com" \
  -H "X-Title: Raycast YouTube Transcript Summarizer" \
  --data "$OR_PAYLOAD" \
)" || die "OpenRouter call failed (see details above)."

OUT="$(echo "$OR_RESP" | jq -r '.choices[0].message.content // empty' 2>/dev/null || true)"
[[ -n "$OUT" ]] || die "OpenRouter returned no message content (see response above)."

# Copy result to clipboard (required)
printf "%s" "$OUT" | pbcopy

echo "$OUT"
hr
echo "Copied output to clipboard."
echo "Transcript source: direct(lang=${CAPTION_LANG:-none}, auto=${CAPTION_AUTO:-?}) ${APIFY_META:+| $APIFY_META}"
