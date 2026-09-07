from django.shortcuts import render
from django.http import JsonResponse, StreamingHttpResponse
from django.views.decorators.csrf import csrf_exempt
from .services import analyze_url, analyze_url_stream
import json

def landing(request):
    return render(request, 'analyzer/landing.html')

def analyze(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format"}, status=400)
        url = data.get('url', '')
        result = analyze_url(url)
        return JsonResponse(result)
        
    return render(request, 'analyzer/index.html')
@csrf_exempt
def analyze_stream(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format"}, status=400)
        
        url = data.get('url', '')
        if not url:
            return JsonResponse({"error": "No URL provided"}, status=400)
            
        def event_generator():
            for event in analyze_url_stream(url):
                yield f"data: {json.dumps(event)}\n\n"
                
        response = StreamingHttpResponse(event_generator(), content_type="text/event-stream")
        response['Cache-Control'] = 'no-cache'
        response['X-Accel-Buffering'] = 'no'  # Prevents Nginx from buffering the stream
        return response
        
    return JsonResponse({"error": "Only POST is supported for streaming analysis"}, status=405)