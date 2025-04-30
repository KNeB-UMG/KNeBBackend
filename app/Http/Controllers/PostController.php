<?php

namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use OpenApi\Attributes as OA;

#[OA\Tag(
    name: 'Posts',
    description: 'API Endpoints for managing posts'
)]
class PostController extends Controller
{
    #[OA\Get(
        path: '/api/posts',
        description: 'Get list of all regular posts (super_event = false)',
        summary: 'List all regular posts',
        parameters: [
            new OA\Parameter(
                name: 'page',
                description: 'Page number',
                in: 'query',
                required: false,
                schema: new OA\Schema(type: 'integer', default: 1)
            ),
            new OA\Parameter(
                name: 'per_page',
                description: 'Number of items per page',
                in: 'query',
                required: false,
                schema: new OA\Schema(type: 'integer', default: 3)
            ),
            new OA\Parameter(
                name: 'sort',
                description: 'Sort order for posts',
                in: 'query',
                required: false,
                schema: new OA\Schema(type: 'string', default: 'newest', enum: ['newest', 'oldest'])
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Successful operation',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(
                            property: 'posts',
                            type: 'array',
                            items: new OA\Items(
                                properties: [
                                    new OA\Property(property: 'id', type: 'integer'),
                                    new OA\Property(property: 'title', type: 'string'),
                                    new OA\Property(property: 'content', type: 'string'),
                                    new OA\Property(property: 'author', type: 'string'),
                                    new OA\Property(property: 'created_at', type: 'string', format: 'date-time'),
                                    new OA\Property(property: 'updated_at', type: 'string', format: 'date-time'),
                                    new OA\Property(
                                        property: 'file',
                                        properties: [
                                            new OA\Property(property: 'id', type: 'integer'),
                                            new OA\Property(property: 'url', type: 'string')
                                        ],
                                        type: 'object',
                                        nullable: true
                                    )
                                ]
                            )
                        ),
                        new OA\Property(property: 'total', type: 'integer'),
                        new OA\Property(property: 'current_page', type: 'integer'),
                        new OA\Property(property: 'per_page', type: 'integer'),
                        new OA\Property(property: 'last_page', type: 'integer')
                    ]
                )
            )
        ]
    )]
    public function regularPosts(Request $request): JsonResponse
    {
        $perPage = $request->query('per_page', 3); // Zmieniono z 15 na 3
        $sortDirection = $request->query('sort', 'newest') === 'newest' ? 'desc' : 'asc';

        $query = Post::with(['author', 'file'])
            ->where('super_event', false)
            ->where('visible', true);

        $query->orderBy('created_at', $sortDirection);

        $posts = $query->paginate($perPage);

        $formattedPosts = [];

        foreach ($posts as $post) {
            $formattedPost = [
                'id' => $post->id,
                'title' => $post->title,
                'content' => $post->content,
                'author' => $post->author->name ?? null,
                'created_at' => $post->created_at,
                'updated_at' => $post->updated_at,
            ];

            if ($post->file_id && $post->file) {
                $formattedPost['file'] = [
                    'id' => $post->file->id,
                    'url' => $post->file->url ?? null,
                ];
            }

            $formattedPosts[] = $formattedPost;
        }

        return response()->json([
            'posts' => $formattedPosts,
            'total' => $posts->total(),
            'current_page' => $posts->currentPage(),
            'per_page' => $posts->perPage(),
            'last_page' => $posts->lastPage()
        ]);
    }

    #[OA\Get(
        path: '/api/posts/super_events',
        description: 'Get list of all posts marked as super events (super_event = true)',
        summary: 'List all super events',
        parameters: [
            new OA\Parameter(
                name: 'page',
                description: 'Page number',
                in: 'query',
                required: false,
                schema: new OA\Schema(type: 'integer', default: 1)
            ),
            new OA\Parameter(
                name: 'per_page',
                description: 'Number of items per page',
                in: 'query',
                required: false,
                schema: new OA\Schema(type: 'integer', default: 3)
            ),
            new OA\Parameter(
                name: 'sort',
                description: 'Sort order for super events',
                in: 'query',
                required: false,
                schema: new OA\Schema(type: 'string', default: 'newest', enum: ['newest', 'oldest'])
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Successful operation',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(
                            property: 'super_events',
                            type: 'array',
                            items: new OA\Items(
                                properties: [
                                    new OA\Property(property: 'id', type: 'integer'),
                                    new OA\Property(property: 'title', type: 'string'),
                                    new OA\Property(property: 'content', type: 'string'),
                                    new OA\Property(property: 'author', type: 'string'),
                                    new OA\Property(property: 'created_at', type: 'string', format: 'date-time'),
                                    new OA\Property(property: 'updated_at', type: 'string', format: 'date-time'),
                                    new OA\Property(
                                        property: 'file',
                                        properties: [
                                            new OA\Property(property: 'id', type: 'integer'),
                                            new OA\Property(property: 'url', type: 'string')
                                        ],
                                        type: 'object',
                                        nullable: true
                                    )
                                ]
                            )
                        ),
                        new OA\Property(property: 'total', type: 'integer'),
                        new OA\Property(property: 'current_page', type: 'integer'),
                        new OA\Property(property: 'per_page', type: 'integer'),
                        new OA\Property(property: 'last_page', type: 'integer')
                    ]
                )
            )
        ]
    )]
    public function superEvents(Request $request): JsonResponse
    {
        $perPage = $request->query('per_page', 3); // Zmieniono z 15 na 3
        $sortDirection = $request->query('sort', 'newest') === 'newest' ? 'desc' : 'asc';

        $query = Post::with(['author', 'file'])
            ->where('super_event', true)
            ->where('visible', true);

        $query->orderBy('created_at', $sortDirection);

        $posts = $query->paginate($perPage);

        $formattedPosts = [];

        foreach ($posts as $post) {
            $formattedPost = [
                'id' => $post->id,
                'title' => $post->title,
                'content' => $post->content,
                'author' => $post->author->name ?? null,
                'created_at' => $post->created_at,
                'updated_at' => $post->updated_at,
            ];

            if ($post->file_id && $post->file) {
                $formattedPost['file'] = [
                    'id' => $post->file->id,
                    'url' => $post->file->url ?? null,
                ];
            }

            $formattedPosts[] = $formattedPost;
        }

        return response()->json([
            'super_events' => $formattedPosts,
            'total' => $posts->total(),
            'current_page' => $posts->currentPage(),
            'per_page' => $posts->perPage(),
            'last_page' => $posts->lastPage()
        ]);
    }

    #[OA\Post(
        path: '/api/posts/store',
        description: 'Create a new post',
        summary: 'Create a new post',
        security: [['sanctum' => []]],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['title', 'content'],
                properties: [
                    new OA\Property(property: 'title', type: 'string', example: 'New Post Title'),
                    new OA\Property(property: 'content', type: 'string', example: 'This is the content of the new post'),
                    new OA\Property(property: 'file_id', type: 'integer', nullable: true, example: 1)
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 201,
                description: 'Post created successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Post został pomyślnie dodany! Teraz czeka na weryfikację administratora, aby stać się widocznym.'),
                        new OA\Property(
                            property: 'post',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'title', type: 'string'),
                                new OA\Property(property: 'content', type: 'string'),
                                new OA\Property(property: 'author_id', type: 'integer'),
                                new OA\Property(property: 'file_id', type: 'integer', nullable: true),
                                new OA\Property(property: 'visible', type: 'boolean'),
                                new OA\Property(property: 'super_event', type: 'boolean'),
                                new OA\Property(property: 'created_at', type: 'string', format: 'date-time'),
                                new OA\Property(property: 'updated_at', type: 'string', format: 'date-time')
                            ],
                            type: 'object'
                        )
                    ]
                )
            ),
            new OA\Response(
                response: 401,
                description: 'Unauthorized',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Brak autoryzacji. Zaloguj się, aby dodać post.')
                    ]
                )
            ),
            new OA\Response(
                response: 403,
                description: 'Forbidden',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Nie masz uprawnień do dodawania postów. Wymagana jest rola admin lub Członek Koła.')
                    ]
                )
            ),
            new OA\Response(
                response: 422,
                description: 'Validation error',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Nie udało się dodać posta. Sprawdź poprawność wprowadzonych danych.'),
                        new OA\Property(
                            property: 'errors',
                            type: 'object'
                        )
                    ]
                )
            )
        ]
    )]
    public function store(Request $request): JsonResponse
    {
        $user = $request->user();

        if (!in_array($user->role, ['admin', 'Członek Koła'])) {
            return response()->json([
                'message' => 'Nie masz uprawnień do dodawania postów. Wymagana jest rola admin lub Członek Koła.'
            ], 403);
        }

        try {
            $validatedData = $request->validate([
                'title' => 'required|string|max:255',
                'content' => 'required|string',
                'file_id' => 'nullable|integer|exists:files,id'
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'message' => 'Nie udało się dodać posta. Sprawdź poprawność wprowadzonych danych.',
                'errors' => $e->errors()
            ], 422);
        }

        try {
            $post = new Post();
            $post->title = $validatedData['title'];
            $post->content = $validatedData['content'];
            $post->author_id = $user->id;
            $post->file_id = $validatedData['file_id'] ?? null;
            $post->visible = false;
            $post->super_event = false;
            $post->edit_history = [
                [
                    'timestamp' => now()->toIso8601String(),
                    'user_id' => $user->id,
                    'user_name' => $user->full_name ?? $user->name,
                    'action' => 'created'
                ]
            ];
            $post->save();

            return response()->json([
                'message' => 'Post został pomyślnie dodany! Teraz czeka na weryfikację administratora, aby stać się widocznym.',
                'post' => $post
            ], 201);
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'Wystąpił błąd podczas dodawania posta. Spróbuj ponownie później.',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    #[OA\Put(
        path: '/api/admin/posts/{id}/update-status',
        description: 'Update visibility and super_event status for a post (Admin only)',
        summary: 'Update post status',
        security: [['sanctum' => []]],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                properties: [
                    new OA\Property(property: 'visible', type: 'boolean', example: true),
                    new OA\Property(property: 'super_event', type: 'boolean', example: false)
                ]
            )
        ),
        parameters: [
            new OA\Parameter(
                name: 'id',
                description: 'Post ID',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'integer')
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Status updated successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Status posta został zaktualizowany'),
                        new OA\Property(
                            property: 'post',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'title', type: 'string'),
                                new OA\Property(property: 'visible', type: 'boolean'),
                                new OA\Property(property: 'super_event', type: 'boolean')
                            ],
                            type: 'object'
                        )
                    ]
                )
            ),
            new OA\Response(
                response: 403,
                description: 'Unauthorized',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Nie masz uprawnień do edycji statusu posta')
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: 'Post not found',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Post nie został znaleziony')
                    ]
                )
            ),
            new OA\Response(
                response: 422,
                description: 'Validation error',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Błąd wpisane danych'),
                        new OA\Property(
                            property: 'errors',
                            type: 'object'
                        )
                    ]
                )
            )
        ]
    )]
    public function updateStatus(Request $request, int $id): JsonResponse
    {
        $post = Post::findOrFail($id);

        $user = $request->user();
        if ($user->role !== 'admin') {
            return response()->json([
                'message' => 'Nie masz uprawnień do edycji statusu posta'
            ], 403);
        }

        try {
            $validatedData = $request->validate([
                'visible' => 'required|boolean',
                'super_event' => 'required|boolean'
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'message' => 'Błąd walidacji danych',
                'errors' => $e->errors()
            ], 422);
        }

        $changes = [];
        if ($validatedData['visible'] !== $post->visible) {
            $changes['visible'] = [
                'from' => $post->visible,
                'to' => $validatedData['visible']
            ];
        }

        if ($validatedData['super_event'] !== $post->super_event) {
            $changes['super_event'] = [
                'from' => $post->super_event,
                'to' => $validatedData['super_event']
            ];
        }

        $editHistory = $post->edit_history ?? [];
        $editHistory[] = [
            'timestamp' => now()->toIso8601String(),
            'user_id' => $user->id,
            'user_name' => $user->full_name ?? $user->name,
            'action' => 'status_updated',
            'changes' => $changes
        ];

        $post->visible = $validatedData['visible'];
        $post->super_event = $validatedData['super_event'];
        $post->edit_history = $editHistory;
        $post->save();

        return response()->json([
            'message' => 'Status posta został zaktualizowany',
            'post' => [
                'id' => $post->id,
                'title' => $post->title,
                'visible' => $post->visible,
                'super_event' => $post->super_event
            ]
        ]);
    }
    #[OA\Put(
        path: '/api/posts/{id}',
        description: 'Update an existing post (available for author or admin)',
        summary: 'Update post',
        security: [['sanctum' => []]],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['title', 'content'],
                properties: [
                    new OA\Property(property: 'title', type: 'string', example: 'Updated Post Title'),
                    new OA\Property(property: 'content', type: 'string', example: 'This is the updated content of the post'),
                    new OA\Property(property: 'file_id', type: 'integer', nullable: true, example: 1)
                ]
            )
        ),
        parameters: [
            new OA\Parameter(
                name: 'id',
                description: 'Post ID',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'integer')
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Post updated successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Post został zaktualizowany pomyślnie! Teraz czeka na weryfikację administratora, aby stać się widocznym.'),
                        new OA\Property(
                            property: 'post',
                            type: 'object',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'title', type: 'string'),
                                new OA\Property(property: 'content', type: 'string'),
                                new OA\Property(property: 'author_id', type: 'integer'),
                                new OA\Property(property: 'file_id', type: 'integer', nullable: true),
                                new OA\Property(property: 'visible', type: 'boolean'),
                                new OA\Property(property: 'super_event', type: 'boolean'),
                                new OA\Property(property: 'updated_at', type: 'string', format: 'date-time')
                            ]
                        )
                    ]
                )
            ),
            new OA\Response(
                response: 403,
                description: 'Unauthorized',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Nie masz uprawnień do edycji tego posta')
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: 'Post not found',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Post nie został znaleziony')
                    ]
                )
            ),
            new OA\Response(
                response: 422,
                description: 'Validation error',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Błąd walidacji danych'),
                        new OA\Property(
                            property: 'errors',
                            type: 'object'
                        )
                    ]
                )
            )
        ]
    )]
    public function update(Request $request, int $id): JsonResponse
    {
        $post = Post::findOrFail($id);

        $user = $request->user();
        if ($user->role !== 'admin' && $post->author_id !== $user->id) {
            return response()->json([
                'message' => 'Nie masz uprawnień do edycji tego posta'
            ], 403);
        }

        try {
            $validatedData = $request->validate([
                'title' => 'required|string|max:255',
                'content' => 'required|string',
                'file_id' => 'nullable|integer|exists:files,id'
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'message' => 'Błąd walidacji danych',
                'errors' => $e->errors()
            ], 422);
        }

        $changes = [];

        if ($validatedData['title'] !== $post->title) {
            $changes['title'] = [
                'from' => $post->title,
                'to' => $validatedData['title']
            ];
        }

        if ($validatedData['content'] !== $post->content) {
            $changes['content'] = [
                'from' => 'poprzednia treść',
                'to' => 'nowa treść'
            ];
        }

        if (isset($validatedData['file_id']) && $validatedData['file_id'] != $post->file_id) {
            $changes['file_id'] = [
                'from' => $post->file_id,
                'to' => $validatedData['file_id']
            ];
        }

        $editHistory = $post->edit_history ?? [];
        $editHistory[] = [
            'timestamp' => now()->toIso8601String(),
            'user_id' => $user->id,
            'user_name' => $user->full_name ?? $user->name,
            'action' => 'updated',
            'changes' => $changes
        ];

        $post->title = $validatedData['title'];
        $post->content = $validatedData['content'];
        $post->file_id = $validatedData['file_id'] ?? $post->file_id;
        $post->edit_history = $editHistory;

        $wasVisible = $post->visible;
        $wasSuperEvent = $post->super_event;

        $post->visible = false;

        if ($wasSuperEvent === false) {
            $post->super_event = false;
        }

        if ($wasVisible !== $post->visible) {
            $changes['visible'] = [
                'from' => $wasVisible,
                'to' => $post->visible
            ];
        }

        $post->save();

        return response()->json([
            'message' => 'Post został zaktualizowany pomyślnie! Teraz czeka na weryfikację administratora, aby stać się widocznym.',
            'post' => [
                'id' => $post->id,
                'title' => $post->title,
                'content' => $post->content,
                'author_id' => $post->author_id,
                'file_id' => $post->file_id,
                'visible' => $post->visible,
                'super_event' => $post->super_event,
                'updated_at' => $post->updated_at
            ]
        ]);
    }
}
