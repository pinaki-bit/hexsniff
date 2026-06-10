# Contributing to HexSniff

First off, thank you for considering contributing to HexSniff! We welcome all contributions, from bug reports to new features.

## How to Contribute

1. **Fork the Repository**
2. **Create a Feature Branch:** `git checkout -b feature/amazing-feature`
3. **Commit your changes:** `git commit -m 'Add amazing feature'`
4. **Push to the branch:** `git push origin feature/amazing-feature`
5. **Open a Pull Request**

## Development Guidelines
- **Python Backend:** Ensure code is PEP8 compliant. If you modify `analyzer.py`, ensure your changes operate in **O(1)** complexity per packet to prevent performance regressions.
- **React Frontend:** Use TailwindCSS sparingly; prefer the custom styling system in `index.css` to maintain the Cyberpunk Enterprise aesthetic. Ensure Three.js WebGL components do not leak memory during component unmount.

## Bug Reports
When filing an issue, please include:
- Your OS and Python version
- Steps to reproduce
- Expected vs. actual behavior
- Whether you are using Native deployment or Docker
