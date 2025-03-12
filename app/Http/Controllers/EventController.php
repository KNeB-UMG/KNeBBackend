<?php

namespace App\Http\Controllers;

use App\Models\Event;
use App\Models\File;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use OpenApi\Attributes as OA;

#[OA\Tag(
    name: 'Events',
    description: 'API Endpoints for managing events'
)]
class EventController extends Controller
{
    #[OA\Get(
        path: '/api/events',
        description: 'Get list of visible events with basic information',
        summary: 'List all visible events',
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
                schema: new OA\Schema(type: 'integer', default: 10)
            ),
            new OA\Parameter(
                name: 'date_from',
                description: 'Filter events from this date (YYYY-MM-DD)',
                in: 'query',
                required: false,
                schema: new OA\Schema(type: 'string', format: 'date')
            ),
            new OA\Parameter(
                name: 'date_to',
                description: 'Filter events up to this date (YYYY-MM-DD)',
                in: 'query',
                required: false,
                schema: new OA\Schema(type: 'string', format: 'date')
            ),
            new OA\Parameter(
                name: 'sort',
                description: 'Sort order for events',
                in: 'query',
                required: false,
                schema: new OA\Schema(type: 'string', default: 'upcoming', enum: ['upcoming', 'past', 'newest', 'oldest'])
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Successful operation',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(
                            property: 'events',
                            type: 'array',
                            items: new OA\Items(
                                properties: [
                                    new OA\Property(property: 'id', type: 'integer'),
                                    new OA\Property(property: 'title', type: 'string'),
                                    new OA\Property(property: 'description', type: 'string'),
                                    new OA\Property(property: 'event_path', type: 'string'),
                                    new OA\Property(property: 'event_date', type: 'string', format: 'date-time'),
                                    new OA\Property(property: 'author', type: 'string'),
                                    new OA\Property(property: 'created_at', type: 'string', format: 'date-time'),
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
    public function index(Request $request): JsonResponse
    {
        $perPage = $request->input('per_page', 10);
        $dateFrom = $request->input('date_from');
        $dateTo = $request->input('date_to');
        $sort = $request->input('sort', 'upcoming');

        $query = Event::where('visible', true)->with('author');

        // Apply date filters if provided
        if ($dateFrom) {
            $query->where('event_date', '>=', $dateFrom . ' 00:00:00');
        }

        if ($dateTo) {
            $query->where('event_date', '<=', $dateTo . ' 23:59:59');
        }

        // Apply sorting
        switch ($sort) {
            case 'upcoming':
                // First show events happening today or in the future, then past events
                $now = now()->format('Y-m-d H:i:s');
                $query->orderByRaw("CASE WHEN event_date >= ? THEN 0 ELSE 1 END", [$now])
                    ->orderBy('event_date', 'asc');
                break;
            case 'past':
                // First show recent past events, then upcoming events
                $now = now()->format('Y-m-d H:i:s');
                $query->orderByRaw("CASE WHEN event_date < ? THEN 0 ELSE 1 END", [$now])
                    ->orderBy('event_date', 'desc');
                break;
            case 'newest':
                $query->orderBy('created_at', 'desc');
                break;
            case 'oldest':
                $query->orderBy('created_at', 'asc');
                break;
            default:
                $query->orderBy('event_date', 'desc');
        }

        $events = $query->paginate($perPage);

        return response()->json([
            'events' => $events->map(function ($event) {
                return [
                    'id' => $event->id,
                    'title' => $event->title,
                    'description' => $event->description,
                    'event_path' => $event->event_path,
                    'event_date' => $event->event_date,
                    'author' => $event->author->full_name,
                    'created_at' => $event->created_at
                ];
            }),
            'total' => $events->total(),
            'current_page' => $events->currentPage(),
            'per_page' => $events->perPage(),
            'last_page' => $events->lastPage()
        ]);
    }

    #[OA\Get(
        path: '/api/admin/events',
        description: 'Get list of all events (including not visible ones) with basic information (Admin/Moderator only)',
        summary: 'List all events for administration',
        security: [['sanctum' => []]],
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
                schema: new OA\Schema(type: 'integer', default: 10)
            ),
            new OA\Parameter(
                name: 'date_from',
                description: 'Filter events from this date (YYYY-MM-DD)',
                in: 'query',
                required: false,
                schema: new OA\Schema(type: 'string', format: 'date')
            ),
            new OA\Parameter(
                name: 'date_to',
                description: 'Filter events up to this date (YYYY-MM-DD)',
                in: 'query',
                required: false,
                schema: new OA\Schema(type: 'string', format: 'date')
            ),
            new OA\Parameter(
                name: 'sort',
                description: 'Sort order for events',
                in: 'query',
                required: false,
                schema: new OA\Schema(type: 'string', default: 'upcoming', enum: ['upcoming', 'past', 'newest', 'oldest'])
            ),
            new OA\Parameter(
                name: 'visibility',
                description: 'Filter by visibility status',
                in: 'query',
                required: false,
                schema: new OA\Schema(type: 'string', enum: ['visible', 'hidden', 'all'])
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Successful operation',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(
                            property: 'events',
                            type: 'array',
                            items: new OA\Items(
                                properties: [
                                    new OA\Property(property: 'id', type: 'integer'),
                                    new OA\Property(property: 'title', type: 'string'),
                                    new OA\Property(property: 'description', type: 'string'),
                                    new OA\Property(property: 'event_path', type: 'string'),
                                    new OA\Property(property: 'event_date', type: 'string', format: 'date-time'),
                                    new OA\Property(property: 'visible', type: 'boolean'),
                                    new OA\Property(property: 'author', type: 'string'),
                                    new OA\Property(property: 'created_at', type: 'string', format: 'date-time'),
                                ]
                            )
                        ),
                        new OA\Property(property: 'total', type: 'integer'),
                        new OA\Property(property: 'current_page', type: 'integer'),
                        new OA\Property(property: 'per_page', type: 'integer'),
                        new OA\Property(property: 'last_page', type: 'integer')
                    ]
                )
            ),
            new OA\Response(
                response: 403,
                description: 'Unauthorized',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            )
        ]
    )]
    public function adminIndex(Request $request): JsonResponse
    {
        // Check permissions
        if (!Auth::user()->hasAnyPermission(['manage_content'])) {
            return response()->json([
                'message' => 'Unauthorized. Admin or moderator access required.'
            ], 403);
        }

        $perPage = $request->input('per_page', 10);
        $dateFrom = $request->input('date_from');
        $dateTo = $request->input('date_to');
        $sort = $request->input('sort', 'upcoming');
        $visibility = $request->input('visibility', 'all');

        $query = Event::with('author');

        // Apply visibility filter
        if ($visibility === 'visible') {
            $query->where('visible', true);
        } else if ($visibility === 'hidden') {
            $query->where('visible', false);
        }

        // Apply date filters if provided
        if ($dateFrom) {
            $query->where('event_date', '>=', $dateFrom . ' 00:00:00');
        }

        if ($dateTo) {
            $query->where('event_date', '<=', $dateTo . ' 23:59:59');
        }

        // Apply sorting
        switch ($sort) {
            case 'upcoming':
                // First show events happening today or in the future, then past events
                $now = now()->format('Y-m-d H:i:s');
                $query->orderByRaw("CASE WHEN event_date >= ? THEN 0 ELSE 1 END", [$now])
                    ->orderBy('event_date', 'asc');
                break;
            case 'past':
                // First show recent past events, then upcoming events
                $now = now()->format('Y-m-d H:i:s');
                $query->orderByRaw("CASE WHEN event_date < ? THEN 0 ELSE 1 END", [$now])
                    ->orderBy('event_date', 'desc');
                break;
            case 'newest':
                $query->orderBy('created_at', 'desc');
                break;
            case 'oldest':
                $query->orderBy('created_at', 'asc');
                break;
            default:
                $query->orderBy('event_date', 'desc');
        }

        $events = $query->paginate($perPage);

        return response()->json([
            'events' => $events->map(function ($event) {
                return [
                    'id' => $event->id,
                    'title' => $event->title,
                    'description' => $event->description,
                    'event_path' => $event->event_path,
                    'event_date' => $event->event_date,
                    'visible' => $event->visible,
                    'author' => $event->author->full_name,
                    'created_at' => $event->created_at
                ];
            }),
            'total' => $events->total(),
            'current_page' => $events->currentPage(),
            'per_page' => $events->perPage(),
            'last_page' => $events->lastPage()
        ]);
    }

    #[OA\Get(
        path: '/api/events/{path}',
        description: 'Get a specific event by its path',
        summary: 'Get event details',
        parameters: [
            new OA\Parameter(
                name: 'path',
                description: 'Event path',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'string')
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Successful operation',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(
                            property: 'event',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'title', type: 'string'),
                                new OA\Property(property: 'content', type: 'string'),
                                new OA\Property(property: 'description', type: 'string'),
                                new OA\Property(property: 'event_path', type: 'string'),
                                new OA\Property(property: 'event_date', type: 'string', format: 'date-time'),
                                new OA\Property(property: 'file', type: 'object', nullable: true),
                                new OA\Property(
                                    property: 'author',
                                    properties: [
                                        new OA\Property(property: 'id', type: 'integer'),
                                        new OA\Property(property: 'full_name', type: 'string')
                                    ],
                                    type: 'object'
                                ),
                                new OA\Property(property: 'created_at', type: 'string', format: 'date-time'),
                                new OA\Property(property: 'updated_at', type: 'string', format: 'date-time')
                            ],
                            type: 'object'
                        )
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: 'Event not found or not visible',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            )
        ]
    )]
    public function show(string $path): JsonResponse
    {
        $event = Event::where('event_path', $path)
            ->where('visible', true)
            ->with(['author', 'file'])
            ->first();

        if (!$event) {
            return response()->json([
                'message' => 'Event not found or not visible'
            ], 404);
        }

        // Format file data if exists
        $fileData = null;
        if ($event->file) {
            $fileData = [
                'id' => $event->file->id,
                'url' => url("api/files/{$event->file->id}"),
                'original_name' => $event->file->original_name,
                'mime_type' => $event->file->mime_type
            ];
        }

        return response()->json([
            'event' => [
                'id' => $event->id,
                'title' => $event->title,
                'content' => $event->content,
                'description' => $event->description,
                'event_path' => $event->event_path,
                'event_date' => $event->event_date,
                'file' => $fileData,
                'author' => [
                    'id' => $event->author->id,
                    'full_name' => $event->author->full_name
                ],
                'created_at' => $event->created_at,
                'updated_at' => $event->updated_at
            ]
        ]);
    }

    #[OA\Get(
        path: '/api/admin/events/{id}',
        description: 'Get a specific event by ID (including non-visible ones)',
        summary: 'Get event details for administration',
        security: [['sanctum' => []]],
        parameters: [
            new OA\Parameter(
                name: 'id',
                description: 'Event ID',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'integer')
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Successful operation',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(
                            property: 'event',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'title', type: 'string'),
                                new OA\Property(property: 'content', type: 'string'),
                                new OA\Property(property: 'description', type: 'string'),
                                new OA\Property(property: 'event_path', type: 'string'),
                                new OA\Property(property: 'event_date', type: 'string', format: 'date-time'),
                                new OA\Property(property: 'visible', type: 'boolean'),
                                new OA\Property(property: 'file', type: 'object', nullable: true),
                                new OA\Property(
                                    property: 'author',
                                    properties: [
                                        new OA\Property(property: 'id', type: 'integer'),
                                        new OA\Property(property: 'full_name', type: 'string')
                                    ],
                                    type: 'object'
                                ),
                                new OA\Property(property: 'edit_history', type: 'array', items: new OA\Items()),
                                new OA\Property(property: 'created_at', type: 'string', format: 'date-time'),
                                new OA\Property(property: 'updated_at', type: 'string', format: 'date-time')
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
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: 'Event not found',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            )
        ]
    )]
    public function adminShow(int $id): JsonResponse
    {
        // Check permissions
        if (!Auth::user()->hasAnyPermission(['manage_content'])) {
            return response()->json([
                'message' => 'Unauthorized. Admin or moderator access required.'
            ], 403);
        }

        $event = Event::with(['author', 'file'])
            ->find($id);

        if (!$event) {
            return response()->json([
                'message' => 'Event not found'
            ], 404);
        }

        // Format file data if exists
        $fileData = null;
        if ($event->file) {
            $fileData = [
                'id' => $event->file->id,
                'url' => url("api/files/{$event->file->id}"),
                'original_name' => $event->file->original_name,
                'mime_type' => $event->file->mime_type
            ];
        }

        return response()->json([
            'event' => [
                'id' => $event->id,
                'title' => $event->title,
                'content' => $event->content,
                'description' => $event->description,
                'event_path' => $event->event_path,
                'event_date' => $event->event_date,
                'visible' => $event->visible,
                'file' => $fileData,
                'author' => [
                    'id' => $event->author->id,
                    'full_name' => $event->author->full_name
                ],
                'edit_history' => $event->edit_history,
                'created_at' => $event->created_at,
                'updated_at' => $event->updated_at
            ]
        ]);
    }

    #[OA\Post(
        path: '/api/events',
        description: 'Create a new event',
        summary: 'Create event',
        security: [['sanctum' => []]],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['title', 'content', 'description', 'event_date'],
                properties: [
                    new OA\Property(property: 'title', type: 'string'),
                    new OA\Property(property: 'content', type: 'string'),
                    new OA\Property(property: 'description', type: 'string'),
                    new OA\Property(property: 'event_date', type: 'string', format: 'date-time'),
                    new OA\Property(property: 'file_id', type: 'integer')
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 201,
                description: 'Event created successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(
                            property: 'event',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'title', type: 'string'),
                                new OA\Property(property: 'event_path', type: 'string')
                            ],
                            type: 'object'
                        )
                    ]
                )
            ),
            new OA\Response(
                response: 401,
                description: 'Unauthenticated',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            ),
            new OA\Response(
                response: 422,
                description: 'Validation error',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(property: 'errors', type: 'object')
                    ]
                )
            )
        ]
    )]
    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'title' => 'required|string|max:255',
            'content' => 'required|string',
            'description' => 'required|string|max:500',
            'event_date' => 'required|date',
            'file_id' => 'nullable|exists:files,id'
        ]);

        // Generate path from title
        $eventPath = Event::generatePath($validated['title']);

        $event = Event::create([
            'title' => $validated['title'],
            'content' => $validated['content'],
            'description' => $validated['description'],
            'event_path' => $eventPath,
            'event_date' => $validated['event_date'],
            'visible' => false, // New events are not visible by default
            'file_id' => $validated['file_id'] ?? null,
            'author_id' => Auth::id(),
            'edit_history' => [
                [
                    'timestamp' => now()->toIso8601String(),
                    'user_id' => Auth::id(),
                    'user_name' => Auth::user()->full_name,
                    'action' => 'created'
                ]
            ]
        ]);

        return response()->json([
            'message' => 'Event created successfully. It will be visible after admin approval.',
            'event' => [
                'id' => $event->id,
                'title' => $event->title,
                'event_path' => $event->event_path
            ]
        ], 201);
    }

    #[OA\Put(
        path: '/api/events/{id}',
        description: 'Update an existing event (own non-visible events or any event for admin/moderator)',
        summary: 'Update event',
        security: [['sanctum' => []]],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                properties: [
                    new OA\Property(property: 'title', type: 'string'),
                    new OA\Property(property: 'content', type: 'string'),
                    new OA\Property(property: 'description', type: 'string'),
                    new OA\Property(property: 'event_date', type: 'string', format: 'date-time'),
                    new OA\Property(property: 'file_id', type: 'integer')
                ]
            )
        ),
        parameters: [
            new OA\Parameter(
                name: 'id',
                description: 'Event ID',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'integer')
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Event updated successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(
                            property: 'event',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'title', type: 'string'),
                                new OA\Property(property: 'event_path', type: 'string')
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
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: 'Event not found',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            ),
            new OA\Response(
                response: 422,
                description: 'Validation error',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(property: 'errors', type: 'object')
                    ]
                )
            )
        ]
    )]
    public function update(Request $request, int $id): JsonResponse
    {
        $event = Event::findOrFail($id);

        // Check if user can edit
        if (!$event->canBeEditedBy(Auth::user())) {
            return response()->json([
                'message' => 'You do not have permission to edit this event'
            ], 403);
        }

        $validated = $request->validate([
            'title' => 'sometimes|required|string|max:255',
            'content' => 'sometimes|required|string',
            'description' => 'sometimes|required|string|max:500',
            'event_date' => 'sometimes|required|date',
            'file_id' => 'sometimes|nullable|exists:files,id'
        ]);

        // Track changes for edit history
        $changes = [];
        $oldEvent = $event->toArray();

        // Update event_path if title changes
        if (isset($validated['title']) && $validated['title'] !== $event->title) {
            $validated['event_path'] = Event::generatePath($validated['title']);
            $changes['title'] = [
                'from' => $event->title,
                'to' => $validated['title']
            ];
        }

        if (isset($validated['content']) && $validated['content'] !== $event->content) {
            $changes['content'] = [
                'from' => 'previous content',
                'to' => 'new content'
            ];
        }

        if (isset($validated['description']) && $validated['description'] !== $event->description) {
            $changes['description'] = [
                'from' => $event->description,
                'to' => $validated['description']
            ];
        }

        if (isset($validated['event_date']) && $validated['event_date'] != $event->event_date) {
            $changes['event_date'] = [
                'from' => $event->event_date,
                'to' => $validated['event_date']
            ];
        }

        if (isset($validated['file_id']) && $validated['file_id'] != $event->file_id) {
            $changes['file_id'] = [
                'from' => $event->file_id,
                'to' => $validated['file_id']
            ];
        }

        // Update edit history
        $editHistory = $event->edit_history ?? [];
        $editHistory[] = [
            'timestamp' => now()->toIso8601String(),
            'user_id' => Auth::id(),
            'user_name' => Auth::user()->full_name,
            'action' => 'updated',
            'changes' => $changes
        ];

        $validated['edit_history'] = $editHistory;

        // Make visible false if edited by the author and not admin/moderator
        if (!Auth::user()->hasAnyPermission(['manage_content']) && $event->author_id === Auth::id()) {
            $validated['visible'] = false;
        }

        $event->update($validated);

        return response()->json([
            'message' => 'Event updated successfully',
            'event' => [
                'id' => $event->id,
                'title' => $event->title,
                'event_path' => $event->event_path,
                'visible' => $event->visible
            ]
        ]);
    }

    #[OA\Put(
        path: '/api/admin/events/{id}/visibility',
        description: 'Change event visibility (Admin only)',
        summary: 'Toggle event visibility',
        security: [['sanctum' => []]],
        parameters: [
            new OA\Parameter(
                name: 'id',
                description: 'Event ID',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'integer')
            )
        ],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['visible'],
                properties: [
                    new OA\Property(property: 'visible', type: 'boolean')
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 200,
                description: 'Visibility updated successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(
                            property: 'event',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'title', type: 'string'),
                                new OA\Property(property: 'visible', type: 'boolean')
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
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: 'Event not found',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            )
        ]
    )]
    public function updateVisibility(Request $request, int $id): JsonResponse
    {
        $event = Event::findOrFail($id);

        // Check if user can change visibility (admin only)
        if (!$event->visibilityCanBeChangedBy(Auth::user())) {
            return response()->json([
                'message' => 'You do not have permission to change visibility of this event'
            ], 403);
        }

        $validated = $request->validate([
            'visible' => 'required|boolean'
        ]);

        // Update edit history
        $editHistory = $event->edit_history ?? [];
        $editHistory[] = [
            'timestamp' => now()->toIso8601String(),
            'user_id' => Auth::id(),
            'user_name' => Auth::user()->full_name,
            'action' => $validated['visible'] ? 'published' : 'unpublished'
        ];

        $event->update([
            'visible' => $validated['visible'],
            'edit_history' => $editHistory
        ]);

        return response()->json([
            'message' => 'Event visibility updated successfully',
            'event' => [
                'id' => $event->id,
                'title' => $event->title,
                'visible' => $event->visible
            ]
        ]);
    }

    #[OA\Delete(
        path: '/api/events/{id}',
        description: 'Delete an event (Admin and Moderator only)',
        summary: 'Delete event',
        security: [['sanctum' => []]],
        parameters: [
            new OA\Parameter(
                name: 'id',
                description: 'Event ID',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'integer')
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Event deleted successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            ),
            new OA\Response(
                response: 403,
                description: 'Unauthorized',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: 'Event not found',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            )
        ]
    )]
    public function destroy(int $id): JsonResponse
    {
        $event = Event::findOrFail($id);

        // Check if user can delete
        if (!$event->canBeDeletedBy(Auth::user())) {
            return response()->json([
                'message' => 'You do not have permission to delete this event'
            ], 403);
        }

        $event->delete();

        return response()->json([
            'message' => 'Event deleted successfully'
        ]);
    }
}
