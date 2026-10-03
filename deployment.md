# 🚀 Deployment Guide: ThreatWeave

The absolute best and easiest way to deploy this project for free is using **Streamlit Community Cloud**. It connects directly to your GitHub repository and automatically hosts the web app.

---

### Step 1: Push to GitHub
1. Make sure you have created a repository on GitHub.
2. Commit and push your local codebase to GitHub:
   ```bash
   git add .
   git commit -m "Ready for deployment"
   git push origin main
   ```
*(Note: Because of our `.gitignore`, your API keys in `.env` and `testing.py` will stay safe on your computer and will **not** be pushed to GitHub!)*

### Step 2: Deploy on Streamlit Cloud
1. Go to [share.streamlit.io](https://share.streamlit.io/) and log in with your GitHub account.
2. Click the **"New app"** button.
3. Fill in the deployment details:
   - **Repository**: Select your GitHub repository (e.g., `yourusername/CTI`)
   - **Branch**: `main`
   - **Main file path**: `src/threatweave/app.py`
4. **DO NOT click Deploy yet!** Proceed to Step 3.

### Step 3: Add Your API Keys (Secrets)
Since your `.env` file was (correctly) not uploaded to GitHub, the cloud server doesn't have your API keys. You have to give them to Streamlit securely.

1. On the deployment screen, click **"Advanced settings..."**
2. Look for the **"Secrets"** text box.
3. Paste the contents of your local `.env` file directly into this box. It should look exactly like this:

```toml
# AI Models
NVIDIA_API_KEY="nvapi-adcXQL..."
LLM_MODEL="nvidia/nemotron-3.5-lightning-30b-a3b"

# Search and Embedding
QDRANT_MODE="persistent"
EMBEDDING_MODEL="sentence-transformers/all-MiniLM-L6-v2"

# Enrichment (Optional but recommended)
ALIENVAULT_API_KEY="your_otx_key"
```
4. Click **Save**.

### Step 4: Launch!
1. Click the **Deploy!** button.
2. Streamlit will now read your `requirements.txt`, install all the libraries, and launch your UI on a public URL!
3. You can now share this URL on your LinkedIn or resume so recruiters can test your AI pipeline in real-time!
