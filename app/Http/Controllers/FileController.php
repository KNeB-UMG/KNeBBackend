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
                        new OA\Property(property: 'message', type: 'string'),
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
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(property: 'errors', type: 'object'),
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
            'message' => 'File uploaded successfully',
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
                content: new OA\MediaType(mediaType: 'application/octet-stream')
            ),
            new OA\Response(
                response: 403,
                description: 'Access denied',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: 'File not found',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
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
                    'message' => 'You do not have permission to access this file'
                ], 403);
            }
        } elseif ($file->permissions === 'members') {
            // Only authenticated users can access member files
            if (!Auth::check()) {
                return response()->json([
                    'message' => 'Authentication required to access this file'
                ], 403);
            }
        }

        // Check if file exists in storage using the uploads disk
        if (!Storage::disk('uploads')->exists($file->file_path)) {
            return response()->json([
                'message' => 'File not found on storage'
            ], 404);
        }

        return response()->download(
            Storage::disk('uploads')->path($file->file_path),
            $file->original_name,
            ['Content-Type' => $file->mime_type]
        );
    }
}
