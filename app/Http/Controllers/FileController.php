<?php

namespace App\Http\Controllers;

use App\Models\File;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use OpenApi\Attributes as OA;

#[OA\Tag(
    name: 'Files',
    description: 'API Endpoints for managing files'
)]
class FileController extends Controller
{
    #[OA\Post(
        path: '/api/files/upload',
        description: 'Upload a file',
        summary: 'Upload a file to the server',
        security: [['sanctum' => []]],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\MediaType(
                mediaType: 'multipart/form-data',
                schema: new OA\Schema(
                    required: ['file'],
                    properties: [
                        new OA\Property(
                            property: 'file',
                            type: 'string',
                            format: 'binary'
                        ),
                        new OA\Property(
                            property: 'category',
                            type: 'string',
                            enum: ['document', 'image', 'other']
                        ),
                        new OA\Property(
                            property: 'permissions',
                            type: 'string',
                            enum: ['public', 'private', 'members']
                        ),
                    ]
                )
            )
        ),
        responses: [
            new OA\Response(
                response: 201,
                description: 'File uploaded successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Plik został pomyślnie przesłany'),
                        new OA\Property(
                            property: 'file',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'original_name', type: 'string'),
                                new OA\Property(property: 'file_path', type: 'string'),
                                new OA\Property(property: 'mime_type', type: 'string'),
                                new OA\Property(property: 'size', type: 'integer'),
                            ],
                            type: 'object'
                        ),
                    ]
                )
            ),
            new OA\Response(
                response: 422,
                description: 'Validation error',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Błąd walidacji'),
                        new OA\Property(property: 'errors', type: 'object'),
                    ]
                )
            ),
            new OA\Response(
                response: 400,
                description: 'Bad request',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Nieprawidłowe żądanie'),
                    ]
                )
            )
        ]
    )]
    public function upload(Request $request): JsonResponse
    {
        $request->validate([
            'file' => 'required|file|max:10240', // 10MB max
            'category' => 'sometimes|string|in:document,image,other',
            'permissions' => 'sometimes|string|in:public,private,members',
        ]);

        $file = $request->file('file');
        $originalName = $file->getClientOriginalName();
        $mimeType = $file->getMimeType();
        $size = $file->getSize();

        // Determine file type based on MIME type
        $fileType = 'other';
        if (str_contains($mimeType, 'image/')) {
            $fileType = 'image';
        } elseif (in_array($mimeType, [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'text/plain',
        ])) {
            $fileType = 'document';
        }

        // Generate a unique name to prevent overwriting
        $fileName = time() . '_' . Str::random(10) . '.' . $file->getClientOriginalExtension();

        // Store the file in the uploads directory using uploads disk
        $path = $file->storeAs('files', $fileName, 'uploads');

        // Create a database record for the file
        $fileModel = File::create([
            'original_name' => $originalName,
            'file_path' => $path,
            'mime_type' => $mimeType,
            'uploaded_by' => Auth::id(),
            'file_type' => $request->input('file_type', $fileType),
            'category' => $request->input('category', 'other'),
            'permissions' => $request->input('permissions', 'private'),
            'size' => $size
        ]);

        return response()->json([
            'message' => 'Plik został pomyślnie przesłany',
            'file' => [
                'id' => $fileModel->id,
                'original_name' => $fileModel->original_name,
                'file_path' => $fileModel->file_path,
                'mime_type' => $fileModel->mime_type,
                'size' => $fileModel->size,
            ]
        ], 201);
    }

    #[OA\Get(
        path: '/api/files/{id}',
        description: 'Download a file',
        summary: 'Download a file by ID',
        parameters: [
            new OA\Parameter(
                name: 'id',
                description: 'File ID',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'integer')
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'File download',
                content: new OA\MediaType(mediaType: 'application/octet-stream'),
                headers: [
                    new OA\Header(
                        header: 'X-Message',
                        description: 'Success message',
                        schema: new OA\Schema(type: 'string', example: 'Plik został pomyślnie pobrany')
                    )
                ]
            ),
            new OA\Response(
                response: 403,
                description: 'Access denied',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Nie masz uprawnień do dostępu do tego pliku'),
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: 'File not found',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Plik nie został znaleziony'),
                    ]
                )
            )
        ]
    )]
    public function download(int $id)
    {
        $file = File::findOrFail($id);

        // Check file permissions
        if ($file->permissions === 'private') {
            // Only file owner or admin can access private files
            if (!Auth::check() || (Auth::id() !== $file->uploaded_by && !Auth::user()->isAdmin())) {
                return response()->json([
                    'message' => 'Nie masz uprawnień do dostępu do tego pliku'
                ], 403);
            }
        } elseif ($file->permissions === 'members') {
            // Only authenticated users can access member files
            if (!Auth::check()) {
                return response()->json([
                    'message' => 'Wymagana autoryzacja do dostępu do tego pliku'
                ], 403);
            }
        }

        // Check if file exists in storage using the uploads disk
        if (!Storage::disk('uploads')->exists($file->file_path)) {
            return response()->json([
                'message' => 'Plik nie został znaleziony na serwerze'
            ], 404);
        }

        return response()->download(
            Storage::disk('uploads')->path($file->file_path),
            $file->original_name,
            [
                'Content-Type' => $file->mime_type,
                'X-Message' => 'Plik został pomyślnie pobrany'
            ]
        );
    }

    #[OA\Delete(
        path: '/api/files/{id}',
        description: 'Delete a file',
        summary: 'Delete a file by ID',
        security: [['sanctum' => []]],
        parameters: [
            new OA\Parameter(
                name: 'id',
                description: 'File ID',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'integer')
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'File deleted successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Plik został pomyślnie usunięty'),
                    ]
                )
            ),
            new OA\Response(
                response: 403,
                description: 'Access denied',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Nie masz uprawnień do usunięcia tego pliku'),
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: 'File not found',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Plik nie został znaleziony'),
                    ]
                )
            )
        ]
    )]
    public function delete(int $id): JsonResponse
    {
        $file = File::findOrFail($id);

        // Check if user has permission to delete this file
        if (Auth::id() !== $file->uploaded_by && !Auth::user()->isAdmin()) {
            return response()->json([
                'message' => 'Nie masz uprawnień do usunięcia tego pliku'
            ], 403);
        }

        // Delete file from storage
        if (Storage::disk('uploads')->exists($file->file_path)) {
            Storage::disk('uploads')->delete($file->file_path);
        }

        // Delete database record
        $file->delete();

        return response()->json([
            'message' => 'Plik został pomyślnie usunięty'
        ], 200);
    }

    #[OA\Get(
        path: '/api/files',
        description: 'Get list of files',
        summary: 'Get list of files the user has access to',
        security: [['sanctum' => []]],
        parameters: [
            new OA\Parameter(
                name: 'category',
                description: 'Filter by category',
                in: 'query',
                required: false,
                schema: new OA\Schema(
                    type: 'string',
                    enum: ['document', 'image', 'other']
                )
            ),
            new OA\Parameter(
                name: 'page',
                description: 'Page number',
                in: 'query',
                required: false,
                schema: new OA\Schema(type: 'integer', default: 1)
            ),
            new OA\Parameter(
                name: 'per_page',
                description: 'Items per page',
                in: 'query',
                required: false,
                schema: new OA\Schema(type: 'integer', default: 15)
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'List of files',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Lista plików pomyślnie pobrana'),
                        new OA\Property(
                            property: 'files',
                            type: 'array',
                            items: new OA\Items(
                                properties: [
                                    new OA\Property(property: 'id', type: 'integer'),
                                    new OA\Property(property: 'original_name', type: 'string'),
                                    new OA\Property(property: 'file_path', type: 'string'),
                                    new OA\Property(property: 'mime_type', type: 'string'),
                                    new OA\Property(property: 'size', type: 'integer'),
                                    new OA\Property(property: 'category', type: 'string'),
                                    new OA\Property(property: 'permissions', type: 'string'),
                                    new OA\Property(property: 'created_at', type: 'string', format: 'date-time'),
                                ],
                                type: 'object'
                            )
                        ),
                        new OA\Property(
                            property: 'pagination',
                            properties: [
                                new OA\Property(property: 'current_page', type: 'integer'),
                                new OA\Property(property: 'total', type: 'integer'),
                                new OA\Property(property: 'per_page', type: 'integer'),
                                new OA\Property(property: 'last_page', type: 'integer'),
                            ],
                            type: 'object'
                        ),
                    ]
                )
            )
        ]
    )]
    public function index(Request $request): JsonResponse
    {
        $request->validate([
            'category' => 'sometimes|string|in:document,image,other',
            'page' => 'sometimes|integer|min:1',
            'per_page' => 'sometimes|integer|min:1|max:100',
        ]);

        $perPage = $request->input('per_page', 15);
        $query = File::query();

        // Filter by category if provided
        if ($request->has('category')) {
            $query->where('category', $request->category);
        }

        // If user is not admin, only show files they have access to
        if (!Auth::user()->isAdmin()) {
            $query->where(function ($q) {
                $q->where('permissions', 'public')
                    ->orWhere('permissions', 'members')
                    ->orWhere(function ($q2) {
                        $q2->where('permissions', 'private')
                            ->where('uploaded_by', Auth::id());
                    });
            });
        }

        $files = $query->orderBy('created_at', 'desc')->paginate($perPage);

        return response()->json([
            'message' => 'Lista plików pomyślnie pobrana',
            'files' => $files->items(),
            'pagination' => [
                'current_page' => $files->currentPage(),
                'total' => $files->total(),
                'per_page' => $files->perPage(),
                'last_page' => $files->lastPage(),
            ]
        ], 200);
    }
}
