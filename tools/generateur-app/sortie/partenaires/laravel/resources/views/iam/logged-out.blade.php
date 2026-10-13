@extends('iam.layout')

@section('title', 'Déconnecté — Gestion des Partenaires')

@section('content')
    <div class="card" style="text-align:center">
        <h1 style="margin-top:0">Vous êtes déconnecté</h1>
        <p class="muted">Votre session Gestion des Partenaires et votre session IAM ont été fermées.</p>
        <a class="btn btn-primary" href="{{ route('iam.login') }}">Se reconnecter</a>
    </div>
@endsection
