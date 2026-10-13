@extends('iam.layout')

@section('title', 'Accueil — Gestion des Partenaires')

@section('content')
    <div class="card">
        <h1 style="margin-top:0">Bienvenue, {{ $iamUser->name() }}</h1>
        <p class="muted">Les modules et boutons affichés dépendent des permissions transmises par l'IAM
            ({{ count($iamUser->permissions) }} reçue(s){{ $iamUser->isAppAdmin() ? ', dont le joker « * »' : '' }}).</p>
    </div>

    <div class="grid">
        @foreach ($modules as $code => $module)
            @iamcan(...array_values($module['actions']))
                <div class="card">
                    <h3 style="margin-top:0">{{ $module['label'] }}</h3>
                    @iamcan($module['actions']['view'] ?? '-')
                        <a class="btn" href="{{ route($code.'.index') }}">Ouvrir</a>
                    @endiamcan
                    @iamcan($module['actions']['create'] ?? '-')
                        <a class="btn btn-primary" href="{{ route($code.'.create') }}">Créer</a>
                    @endiamcan
                    @iamcan($module['actions']['export'] ?? '-')
                        <a class="btn" href="{{ route($code.'.export') }}">Exporter</a>
                    @endiamcan
                </div>
            @endiamcan
        @endforeach
    </div>
@endsection
