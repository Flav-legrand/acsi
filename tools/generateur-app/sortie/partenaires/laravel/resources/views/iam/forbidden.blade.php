@extends('iam.layout')

@section('title', 'Accès refusé — Gestion des Partenaires')

@section('content')
    <div class="card" style="text-align:center">
        <h1 style="color:#b42318;font-size:42px;margin:8px 0">403</h1>
        <p>{{ $message ?? 'Accès refusé.' }}</p>
        <p class="muted">Si vous pensez avoir besoin de ce droit, contactez l'administrateur IAM.</p>
        <a class="btn" href="{{ url('/') }}">← Accueil</a>
    </div>
@endsection
