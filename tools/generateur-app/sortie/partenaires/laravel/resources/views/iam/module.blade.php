@extends('iam.layout')

@section('title', $label.' — Gestion des Partenaires')

@section('content')
    <div class="card">
        <p class="muted" style="margin:0"><a href="{{ url('/') }}">Accueil</a> › {{ $label }}</p>
        <h1>{{ $label }} — {{ $title }}</h1>
        <p class="muted">Écran de démonstration : la route est protégée par
            <code>iam.permission:{{ $actions[$action] ?? '' }}</code>.</p>

        <p>
            @iamcan($actions['create'] ?? '-')
                <a class="btn btn-primary" href="{{ route($module.'.create') }}">Créer</a>
            @endiamcan
            @iamcan($actions['export'] ?? '-')
                <a class="btn" href="{{ route($module.'.export') }}">Exporter</a>
            @endiamcan
        </p>

        <table>
            <thead><tr><th>#</th><th>Enregistrement</th><th style="text-align:right">Actions</th></tr></thead>
            <tbody>
            @foreach ([1, 2, 3] as $id)
                <tr>
                    <td>{{ $id }}</td>
                    <td>Exemple {{ $id }}</td>
                    <td style="text-align:right">
                        @iamcan($actions['edit'] ?? '-')
                            <a class="btn" href="{{ route($module.'.edit', $id) }}">Modifier</a>
                        @endiamcan
                        @iamcan($actions['delete'] ?? '-')
                            <form method="POST" action="{{ route($module.'.destroy', $id) }}" style="display:inline">
                                @csrf @method('DELETE')
                                <button class="btn btn-danger">Supprimer</button>
                            </form>
                        @endiamcan
                        @if (! $user?->can($actions['edit'] ?? '-') && ! $user?->can($actions['delete'] ?? '-'))
                            <span class="muted">lecture seule</span>
                        @endif
                    </td>
                </tr>
            @endforeach
            </tbody>
        </table>
    </div>
@endsection
