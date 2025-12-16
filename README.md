# Link

https://lainctf.github.io/writeups/

# For lainons

To publish your post on https://lainctf.github.io/writeups/

1. Create `src/content/blog/you-blog-post.md` file
2. Write your post using `N0Ps-CTF-Web-Casino.md` for reference
3. `git add . && git commit 'New post' && git push`
4. Wait for build completion
5. ???
6. Profit!

## Check how your post looks before pushing

Install deps (once):
```bash
npm i
```

Build and run:
```bash
npm run build
npm run preview
```

Visit http://localhost:4321/writeups
