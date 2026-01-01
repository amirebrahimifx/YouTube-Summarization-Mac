#YouTube Transcript → AI Summary (Raycast)

A Raycast Script Command that reads a YouTube URL from your clipboard, fetches the video title, extracts the best available transcript (YouTube captions first, Apify fallback), sends it to OpenRouter (Groq-first) for a fast structured summary/Q&A, then copies the result to your clipboard.

What it does
	•	Validates clipboard contains a YouTube URL
	•	Fetches YouTube title automatically
	•	Transcript extraction:
	•	Phase A (free): YouTube timedtext captions
	•	Phase B (fallback): Apify transcript actor (paid)
	•	Calls OpenRouter with Groq-first routing + minimal reasoning
	•	Outputs:
	1.	Story paragraph
	2.	Title-question answer paragraph
	3.	Key points bullets
	4.	10-part timeline (1/10 … 10/10)
	5.	Best quote
	•	Copies the model output to clipboard (pbcopy)

Requirements
	•	macOS + Raycast
	•	curl, jq, python3
	•	Install jq if needed: brew install jq
	•	OpenRouter API key (required)
	•	Apify token (optional but recommended)

#Setup

1) Save keys in Keychain

security add-generic-password -a "$USER" -s "openrouter_api_key" -w "YOUR_OPENROUTER_API_KEY" -U
security add-generic-password -a "$USER" -s "apify_token" -w "YOUR_APIFY_TOKEN" -U

2) Install the script in Raycast
	1.	Raycast → Script Commands → Add Script Directory
	2.	Put the script file there, e.g. youtube-ai-summary.sh
	3.	Make it executable:

chmod +x ~/raycast-scripts/youtube-ai-summary.sh

3) Allow Keychain access (first run)

When prompted, click Always Allow for Raycast.
If it still fails: Keychain Access → item → Access Control → allow Raycast.

Usage
	1.	Copy a YouTube link (e.g. https://youtu.be/...)
	2.	Run the Raycast command
	3.	Read output in Raycast; it is also copied to clipboard

Optional: pass a question as the script argument to do transcript-based Q&A instead of summarizing.

Notes
	•	Some videos have no captions; Apify may return empty in that case (the script prints debug info).
	•	Keep API keys in Keychain; do not hardcode them.

License

Add your preferred license (MIT is common).
