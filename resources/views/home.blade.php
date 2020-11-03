<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sqotify</title>
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <link rel="stylesheet" href="{{ asset('/css/register.css') }}">
</head>
<body>
    <div id="app">
        <app-home />
    </div>
    <script src="{{asset('js/app.js')}}"></script>
</body>
</html>
