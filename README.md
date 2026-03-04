# Wood13nqxy3n's Blog

A modern, minimal, dark-themed personal CTF blog built with **Jekyll** and hosted on **GitHub Pages**.

![Dark Theme](https://img.shields.io/badge/theme-dark-0D1117?style=flat-square)
![Jekyll](https://img.shields.io/badge/built_with-Jekyll-CC0000?style=flat-square)
![GitHub Pages](https://img.shields.io/badge/hosted_on-GitHub_Pages-222?style=flat-square)

---

## Features

- Dark theme by default (with light mode toggle)
- Markdown-powered blog posts
- Syntax highlighting (Rouge) with copy button
- Search posts by title, tag, or content
- **Category system** (CTF → Tournament / Training)
- Tag-based filtering
- Category + tag + search combined filtering
- Table of Contents sidebar on posts (HackMD-style)
- Pagination (10 posts per page)
- Responsive design (desktop, tablet, mobile)
- SEO optimized (meta tags, Open Graph, sitemap, RSS feed)
- Smooth animations
- Fast performance
- Zero dependencies (no jQuery, no frameworks)

---

## Project Structure

```
myblog/
├── _config.yml              # Jekyll configuration
├── _layouts/
│   ├── default.html         # Base layout
│   ├── post.html            # Blog post layout (with TOC)
│   ├── page.html            # Static page layout
│   └── category.html        # Category listing layout
├── _includes/
│   ├── head.html            # <head> meta, fonts, styles
│   ├── navbar.html          # Navigation bar
│   └── footer.html          # Footer
├── _posts/
│   └── ctf/
│       ├── tournament/
│       │   ├── PascalCTF/   # Posts for PascalCTF contest
│       │   ├── BITSCTF/     # Posts for BITSCTF contest
│       │   ├── 0xFUN/       # Posts for 0xFUN contest
│       │   └── UVT/         # Posts for UVT contest
│       └── training/
│           ├── picoCTF/     # picoCTF practice writeups
│           └── Dreamhack/   # Dreamhack practice writeups
├── categories/
│   ├── index.html           # /categories/ overview page
│   ├── tournament.html      # /categories/tournament/ listing
│   └── training.html        # /categories/training/ listing
├── assets/
│   ├── css/
│   │   └── style.css        # All styles
│   └── js/
│       └── main.js          # Theme toggle, search, filters
├── index.html               # Home page (post list + filters)
├── about.md                 # About page
├── 404.html                 # 404 error page
├── Gemfile                  # Ruby dependencies
└── README.md                # This file
```

---

## Deploy to GitHub Pages (Step by Step)

### Option A: User/Organization Site (recommended)

1. **Create a repository** named `<username>.github.io` on GitHub

2. **Clone** this repository:
   ```bash
   git clone https://github.com/<username>/<username>.github.io.git
   cd <username>.github.io
   ```

3. **Copy all files** from this project into the cloned repo

4. **Edit `_config.yml`**:
   ```yaml
   title: Your Blog Name
   description: "Your blog description"
   author: Your Name
   url: "https://<username>.github.io"
   baseurl: ""
   github_username: <your-github-username>
   ```

5. **Push to GitHub**:
   ```bash
   git add .
   git commit -m "Initial blog setup"
   git push origin main
   ```

6. **Enable GitHub Pages** (if not auto-enabled):
   - Go to repository **Settings** → **Pages**
   - Source: **Deploy from a branch**
   - Branch: **main** / **(root)**
   - Click **Save**

7. **Visit** `https://<username>.github.io` — your blog is live!

### Option B: Project Site

1. Create a repository with any name (e.g., `my-blog`)

2. Update `_config.yml`:
   ```yaml
   baseurl: "/my-blog"
   ```

3. Push to GitHub and enable Pages from Settings → Pages

4. Visit `https://<username>.github.io/my-blog`

---

## Writing a New Post

1. Create a new `.md` file in the appropriate category folder:
   ```
   _posts/ctf/tournament/<ContestName>/YYYY-MM-DD-challenge-name.md
   _posts/ctf/training/<Platform>/YYYY-MM-DD-challenge-name.md
   ```

   For example:
   ```
   _posts/ctf/tournament/BITSCTF/2026-03-04-new-challenge.md
   _posts/ctf/training/Dreamhack/2026-03-04-some-exercise.md
   ```

2. Add frontmatter at the top:
   ```markdown
   ---
   title: "Your Post Title"
   date: 2026-03-01
   categories: [CTF, Tournament]
   tags: [ContestName, pwn]
   description: "A brief description of your post."
   ---

   Your content here in Markdown...
   ```

   - Use `categories: [CTF, Tournament]` for contest writeups
   - Use `categories: [CTF, Training]` for practice/training writeups

3. Supported Markdown features:
   - Headings (`# H1` through `###### H6`)
   - **Bold**, *italic*, ~~strikethrough~~
   - Code blocks with syntax highlighting (+ copy button)
   - Images: `![alt](url)`
   - Links: `[text](url)`
   - Tables
   - Blockquotes
   - Ordered and unordered lists

4. Commit and push — GitHub Pages will automatically rebuild.

---

## Category System

Posts are organized under `_posts/ctf/` with two sub-categories:

| Category     | Path                                  | Description              |
|-------------|---------------------------------------|--------------------------|
| Tournament  | `_posts/ctf/tournament/<Contest>/`    | CTF competition writeups |
| Training    | `_posts/ctf/training/<Platform>/`     | Practice/training writeups |

### Adding a New Contest (Tournament)

1. Create a new folder under `_posts/ctf/tournament/`:
   ```bash
   mkdir _posts/ctf/tournament/NewContestName
   ```

2. Add your writeup `.md` files inside:
   ```
   _posts/ctf/tournament/NewContestName/2026-03-04-challenge-name.md
   ```

3. Use this frontmatter:
   ```yaml
   ---
   title: "Challenge Name - NewContest Write Up"
   date: 2026-03-04
   categories: [CTF, Tournament]
   tags: [NewContestName, pwn]
   description: "Writeup description"
   ---
   ```

4. That's it! Jekyll auto-discovers posts in subfolders. The post will appear on the home page and under **Categories → Tournament**.

### Adding a New Training Platform

1. Create a new folder under `_posts/ctf/training/`:
   ```bash
   mkdir _posts/ctf/training/Dreamhack
   ```

2. Add writeup files inside:
   ```
   _posts/ctf/training/Dreamhack/2026-03-04-exercise-name.md
   ```

3. Use this frontmatter:
   ```yaml
   ---
   title: "Exercise Name - Dreamhack Write Up"
   date: 2026-03-04
   categories: [CTF, Training]
   tags: [Dreamhack, web]
   description: "Writeup description"
   ---
   ```

### Adding a Completely New Category (beyond Tournament/Training)

If you want to add a brand new category (e.g., `Research`):

1. Add posts with the new category in frontmatter:
   ```yaml
   categories: [CTF, Research]
   ```

2. Create the folder structure:
   ```bash
   mkdir -p _posts/ctf/research/TopicName
   ```

3. Create a category page at `categories/research.html`:
   ```yaml
   ---
   layout: category
   title: Research
   category: Research
   permalink: /categories/research/
   ---
   ```

4. Update `categories/index.html` to include the new category card.

5. Optionally add a filter button to `index.html`:
   ```html
   <button class="cat-btn" data-category="Research">Research</button>
   ```

---

## Adding Images

Place images in `assets/images/` and reference them in posts:

```markdown
![My Image](/assets/images/my-image.png)
```

---

## Local Development (Optional)

If you want to preview locally before pushing:

```bash
# Install Ruby and Bundler (if not installed)
# See: https://jekyllrb.com/docs/installation/

# Install dependencies
bundle install

# Run local server
bundle exec jekyll serve

# Open http://localhost:4000
```

---

## Customization

### Change Colors

Edit CSS custom properties in `assets/css/style.css`:

```css
:root {
  --bg: #0D1117;
  --surface: #161B22;
  --primary: #58A6FF;
  --text: #C9D1D9;
  /* ... */
}
```

### Change Fonts

Update the Google Fonts import in `_includes/head.html`.

### Add New Pages

Create a new `.md` file in the root with frontmatter:

```markdown
---
layout: page
title: Contact
permalink: /contact/
---

Your content...
```

Then add a link in `_includes/navbar.html`.

---

## License

MIT License. Feel free to use and modify.