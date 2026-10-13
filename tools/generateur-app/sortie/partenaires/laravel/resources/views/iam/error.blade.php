@extends('iam.layout')

@section('title', 'Connexion impossible — Gestion des Partenaires')

@section('content')
    <div class="card">
        <h1 style="margin-top:0">Connexion impossible</h1>
        <p>{{ $message }}</p>
        <a class="btn btn-primary" href="{{ route('iam.login') }}">Réessayer</a>
    </div>
@endsection
