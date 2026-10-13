<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>@yield('title', 'Gestion des Partenaires')</title>
    <style>
        :root { --accent: #0b6e4f; --ink: #1f2933; --muted: #64748b; --line: #e2e8f0; --bg: #f6f8fa; }
        * { box-sizing: border-box; }
        body { margin: 0; font-family: system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--ink); background: var(--bg); }
        header { background: var(--accent); color: #fff; padding: 12px 20px; display: flex; gap: 16px; align-items: center; justify-content: space-between; flex-wrap: wrap; }
        header a, header button { color: #fff; }
        header .who { font-size: 14px; opacity: .95; }
        main { max-width: 1040px; margin: 24px auto; padding: 0 16px; }
        .card { background: #fff; border: 1px solid var(--line); border-radius: 8px; padding: 18px 20px; margin-bottom: 16px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 14px; }
        .btn { display: inline-block; padding: 7px 12px; border-radius: 6px; border: 1px solid var(--accent); color: var(--accent); background: #fff; text-decoration: none; font-size: 14px; cursor: pointer; }
        .btn-primary { background: var(--accent); color: #fff; }
        .btn-danger { border-color: #b42318; color: #b42318; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; background: #eef2f6; font-size: 12px; margin: 2px; }
        .muted { color: var(--muted); }
        .status { background: #ecfdf3; border: 1px solid #abefc6; padding: 10px 14px; border-radius: 6px; margin-bottom: 16px; }
        table { border-collapse: collapse; width: 100%; }
        td, th { border-bottom: 1px solid var(--line); padding: 8px; text-align: left; font-size: 14px; }
        code { font-size: 12px; }
    </style>
</head>
<body>
<header>
    <strong><a href="{{ url('/') }}" style="text-decoration:none">Gestion des Partenaires</a></strong>
    @if ($iamUser)
        <span class="who">
            {{ $iamUser->name() }} — {{ $iamUser->email() }}
            @foreach ($iamUser->roles as $role)<span class="badge" style="color:var(--ink)">{{ $role }}</span>@endforeach
            <span class="badge" style="color:var(--ink)">{{ strtoupper($iamUser->mode) }}</span>
        </span>
        <form method="POST" action="{{ route('iam.logout') }}" style="margin:0">
            @csrf
            <button class="btn" style="background:transparent;border-color:#fff">Se déconnecter</button>
        </form>
    @endif
</header>
<main>
    @if (session('status'))<div class="status">{{ session('status') }}</div>@endif
    @yield('content')
</main>
</body>
</html>
