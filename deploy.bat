@echo off
echo Building LinkCheck AI Docker image...
docker build -t linkcheck-ai .

echo Running LinkCheck AI container...
docker run -d --name linkcheck-ai -p 5000:5000 linkcheck-ai

echo Deployment complete! Access at http://localhost:5000
pause