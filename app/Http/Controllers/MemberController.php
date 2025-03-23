<?php

namespace App\Http\Controllers;

use App\Models\Member;
use App\Models\File;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Auth;
use OpenApi\Attributes as OA;
use Illuminate\Support\Str;
use Illuminate\Validation\Rules\Password;

#[OA\Tag(
    name: 'Members',
    description: 'API Endpoints for managing users'
)]
class MemberController extends Controller
{
    #[OA\Post(
        path: '/api/member/register',
        description: 'Register a new user',
        summary: 'Register a new user',
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['email', 'password','first_name','last_name'],
                properties:[
                    new OA\Property(property: 'email' ,type:'string',format:'email'),
                    new OA\Property(property: 'password' ,type:'string',format:'password'),
                    new OA\Property(property: 'first_name' ,type:'string'),
                    new OA\Property(property: 'last_name' ,type:'string'),
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 201,
                description: 'User successfully registered',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(
                            property: 'user',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'email', type: 'string'),
                                new OA\Property(property: 'full_name', type: 'string'),
                                new OA\Property(property: 'role', type: 'string'),
                            ],
                            type: 'object'
                        ),
                        new OA\Property(property: 'token', type: 'string'),
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
    public function registerMember(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['required','string','email','max:255','unique:members'],
            'password'=>['required',Password::min(8)->mixedCase()->numbers()],
            'first_name' => ['required','string','max:255'],
            'last_name' => ['required','string','max:255'],
        ]);

        $member = Member::create([
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
            'first_name' => $validated['first_name'],
            'last_name' => $validated['last_name'],
            'position'=>"Członek Koła",
            'description'=>null,
            'role'=> Member::ROLE_USER,
            'is_active'=>false,
            'visible'=>false,
            'activation_code' => (string) Str::uuid(),
        ]);

        // TODO: Send activation email with the activation link
        // Mail::to($member->email)->send(new ActivationMail($member));

        return response()->json([
            'message' => 'Użytkownik został pomyślnie zarejestrowany. Sprawdź swoją skrzynkę e-mail, aby aktywować konto.',
        ], 201);
    }

    #[OA\Post(
        path: '/api/admin/member/create',
        description: 'Create a new user account (Admin only)',
        summary: 'Create a new user account with random password',
        security: [['sanctum' => []]],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['email', 'first_name', 'last_name'],
                properties:[
                    new OA\Property(property: 'email', type:'string', format:'email'),
                    new OA\Property(property: 'first_name', type:'string'),
                    new OA\Property(property: 'last_name', type:'string'),
                    new OA\Property(property: 'role', type:'string', enum:[
                        Member::ROLE_USER,
                        Member::ROLE_MODERATOR,
                        Member::ROLE_NONE
                    ]),
                    new OA\Property(property: 'is_active', type:'boolean'),
                    new OA\Property(property: 'visible', type:'boolean'),
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 201,
                description: 'User successfully created',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(
                            property: 'user',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'email', type: 'string'),
                                new OA\Property(property: 'full_name', type: 'string'),
                                new OA\Property(property: 'role', type: 'string'),
                            ],
                            type: 'object'
                        ),
                    ]
                )
            ),
            new OA\Response(
                response: 403,
                description: 'Unauthorized - Admin access required',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
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
    public function createMember(Request $request): JsonResponse
    {
        // Check if user is admin
        if (!Auth::user()->isAdmin()) {
            return response()->json([
                'message' => 'Brak uprawnień. Wymagany dostęp administratora.'
            ], 403);
        }

        $validated = $request->validate([
            'email' => ['required', 'string', 'email', 'max:255', 'unique:members'],
            'first_name' => ['required', 'string', 'max:255'],
            'last_name' => ['required', 'string', 'max:255'],
            'role' => ['sometimes', 'string', 'in:' . implode(',', [
                    Member::ROLE_USER,
                    Member::ROLE_MODERATOR,
                    Member::ROLE_NONE
                ])],
            'is_active' => ['sometimes', 'boolean'],
            'visible' => ['sometimes', 'boolean'],
        ]);

        $randomPassword = Str::random(12);

        $member = Member::create([
            'email' => $validated['email'],
            'password' => Hash::make($randomPassword),
            'first_name' => $validated['first_name'],
            'last_name' => $validated['last_name'],
            'position' => "Członek Koła",
            'description' => null,
            'role' => $validated['role'] ?? Member::ROLE_USER,
            'is_active' => $validated['is_active'] ?? true,
            'visible' => $validated['visible'] ?? false,
            'activation_code' => Str::uuid()
        ]);

        // TODO: Send welcome email with the random password to the user
        // Mail::to($member->email)->send(new WelcomeMail($member, $randomPassword));

        return response()->json([
            'message' => 'Użytkownik został pomyślnie utworzony. Wiadomość powitalna z danymi do logowania zostanie wysłana.',
            'user' => [
                'id' => $member->id,
                'email' => $member->email,
                'full_name' => $member->full_name,
                'role' => $member->role,
            ]
        ], 201);
    }

    #[OA\Post(
        path: '/api/member/login',
        description: 'Login with email and password to receive an API token for future requests',
        summary: 'Authenticate user and get access token',
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['email', 'password'],
                properties: [
                    new OA\Property(
                        property: 'email',
                        type: 'string',
                        format: 'email',
                        example: 'user@example.com'
                    ),
                    new OA\Property(
                        property: 'password',
                        type: 'string',
                        format: 'password',
                        example: 'password123'
                    )
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 200,
                description: 'Login successful',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'token', type: 'string'),
                        new OA\Property(property: 'token_type', type: 'string', example: 'Bearer'),
                        new OA\Property(
                            property: 'user',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'email', type: 'string'),
                                new OA\Property(property: 'full_name', type: 'string'),
                                new OA\Property(property: 'role', type: 'string'),
                                new OA\Property(
                                    property: 'permissions',
                                    type: 'array',
                                    items: new OA\Items(type: 'string')
                                )
                            ],
                            type: 'object'
                        ),
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            ),
            new OA\Response(
                response: 401,
                description: 'Invalid credentials',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Invalid credentials')
                    ]
                )
            ),
            new OA\Response(
                response: 403,
                description: 'Account inactive or no access',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Account is inactive or has no access')
                    ]
                )
            )
        ]
    )]
    public function loginMember(Request $request): JsonResponse
    {
        $credentials = $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required', 'string']
        ]);

        $member = Member::where('email', $credentials['email'])->first();

        if (!$member || !$member->isActiveUser()) {
            return response()->json([
                'message' => 'Konto jest nieaktywne lub nie ma dostępu'
            ], 403);
        }

        if (!Hash::check($credentials['password'], $member->password)) {
            return response()->json([
                'message' => 'Nieprawidłowe dane logowania'
            ], 401);
        }

        $token = $member->createToken('auth_token')->plainTextToken;

        return response()->json([
            'token' => $token,
            'token_type' => 'Bearer',
            'user' => [
                'id' => $member->id,
                'email' => $member->email,
                'full_name' => $member->full_name,
                'role' => $member->role,
                'permissions' => $member->getPermissions()
            ],
            'message' => 'Logowanie zakończone pomyślnie'
        ]);
    }

    #[OA\Post(
        path: '/api/member/deactivate',
        description: 'Deactivate user account (self-deactivation)',
        summary: 'Deactivate own user account',
        security: [['sanctum' => []]],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Account successfully deactivated',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                    ]
                )
            ),
            new OA\Response(
                response: 401,
                description: 'Unauthorized',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            )
        ]
    )]
    public function deactivateOwnAccount(): JsonResponse
    {
        $member = Auth::user();

        $member->is_active = false;
        $member->save();

        // Revoke all tokens
        $member->tokens()->delete();

        return response()->json([
            'message' => 'Twoje konto zostało pomyślnie dezaktywowane'
        ]);
    }

    #[OA\Post(
        path: '/api/admin/member/{id}/deactivate',
        description: 'Deactivate user account (Admin only)',
        summary: 'Deactivate user account by ID',
        security: [['sanctum' => []]],
        parameters: [
            new OA\Parameter(
                name: 'id',
                description: 'Member ID',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'integer')
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Account successfully deactivated',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                    ]
                )
            ),
            new OA\Response(
                response: 403,
                description: 'Unauthorized or trying to deactivate admin account',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: 'User not found',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            )
        ]
    )]
    public function deactivateAccount(int $id): JsonResponse
    {
        // Check if user is admin
        if (!Auth::user()->isAdmin()) {
            return response()->json([
                'message' => 'Brak uprawnień. Wymagany dostęp administratora.'
            ], 403);
        }

        $member = Member::find($id);

        if (!$member) {
            return response()->json([
                'message' => 'Nie znaleziono użytkownika'
            ], 404);
        }

        // Prevent deactivating admin accounts
        if ($member->isAdmin()) {
            return response()->json([
                'message' => 'Konta administratorów nie mogą być dezaktywowane'
            ], 403);
        }

        $member->is_active = false;
        $member->save();

        // Revoke all tokens for the member
        $member->tokens()->delete();

        return response()->json([
            'message' => 'Konto zostało pomyślnie dezaktywowane'
        ]);
    }
    #[OA\Post(
        path: '/api/member/activate/{code}',
        description: 'Activate user account using activation code',
        summary: 'Activate user account',
        parameters: [
            new OA\Parameter(
                name: 'code',
                description: 'Activation code (UUID)',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'string', format: 'uuid')
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Account successfully activated',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: 'Invalid activation code',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            )
        ]
    )]
    public function activateAccount(string $code): JsonResponse
    {
        $member = Member::where('activation_code', $code)->first();

        if (!$member) {
            return response()->json([
                'message' => 'Nieprawidłowy kod aktywacyjny'
            ], 404);
        }

        $member->is_active = true;
        $member->activation_code = null;
        $member->save();

        return response()->json([
            'message' => 'Twoje konto zostało pomyślnie aktywowane'
        ]);
    }
    #[OA\Put(
        path: '/api/admin/member/{id}/role',
        description: 'Change user role (Admin only)',
        summary: 'Update role for a specific user',
        security: [['sanctum' => []]],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['role'],
                properties: [
                    new OA\Property(
                        property: 'role',
                        type: 'string',
                        enum: [
                            Member::ROLE_ADMIN,
                            Member::ROLE_MODERATOR,
                            Member::ROLE_USER,
                            Member::ROLE_NONE
                        ]
                    )
                ]
            )
        ),
        parameters: [
            new OA\Parameter(
                name: 'id',
                description: 'Member ID',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'integer')
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Role updated successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(
                            property: 'user',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'email', type: 'string'),
                                new OA\Property(property: 'full_name', type: 'string'),
                                new OA\Property(property: 'role', type: 'string'),
                            ],
                            type: 'object'
                        )
                    ]
                )
            ),
            new OA\Response(
                response: 403,
                description: 'Unauthorized - Admin access required',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: 'User not found',
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
    public function changeRole(Request $request, int $id): JsonResponse
    {
        // Check if user is admin
        if (!Auth::user()->isAdmin()) {
            return response()->json([
                'message' => 'Brak uprawnień. Wymagany dostęp administratora.'
            ], 403);
        }

        $validated = $request->validate([
            'role' => ['required', 'string', 'in:' . implode(',', Member::getAvailableRoles())]
        ]);

        $member = Member::find($id);

        if (!$member) {
            return response()->json([
                'message' => 'Nie znaleziono użytkownika'
            ], 404);
        }

        $member->role = $validated['role'];
        $member->save();

        return response()->json([
            'message' => 'Rola użytkownika została pomyślnie zaktualizowana',
            'user' => [
                'id' => $member->id,
                'email' => $member->email,
                'full_name' => $member->full_name,
                'role' => $member->role,
            ]
        ]);
    }

    #[OA\Put(
        path: '/api/admin/member/{id}/visibility',
        description: 'Change user visibility (Admin only)',
        summary: 'Update visibility for a specific user',
        security: [['sanctum' => []]],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['visible'],
                properties: [
                    new OA\Property(
                        property: 'visible',
                        type: 'boolean'
                    )
                ]
            )
        ),
        parameters: [
            new OA\Parameter(
                name: 'id',
                description: 'Member ID',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'integer')
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Visibility updated successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(
                            property: 'user',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'email', type: 'string'),
                                new OA\Property(property: 'full_name', type: 'string'),
                                new OA\Property(property: 'visible', type: 'boolean'),
                            ],
                            type: 'object'
                        )
                    ]
                )
            ),
            new OA\Response(
                response: 403,
                description: 'Unauthorized - Admin access required',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: 'User not found',
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
    public function changeVisibility(Request $request, int $id): JsonResponse
    {
        if (!Auth::user()->isAdmin()) {
            return response()->json([
                'message' => 'Brak uprawnień. Wymagany dostęp administratora.'
            ], 403);
        }

        $validated = $request->validate([
            'visible' => ['required', 'boolean']
        ]);

        $member = Member::find($id);

        if (!$member) {
            return response()->json([
                'message' => 'Nie znaleziono użytkownika'
            ], 404);
        }

        $member->visible = $validated['visible'];
        $member->save();

        return response()->json([
            'message' => 'Widoczność użytkownika została pomyślnie zaktualizowana',
            'user' => [
                'id' => $member->id,
                'email' => $member->email,
                'full_name' => $member->full_name,
                'visible' => $member->visible,
            ]
        ]);
    }

    #[OA\Put(
        path: '/api/admin/member/{id}/position',
        description: 'Update user position (Admin only)',
        summary: 'Change position for a specific user',
        security: [['sanctum' => []]],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['position'],
                properties: [
                    new OA\Property(
                        property: 'position',
                        type: 'string'
                    )
                ]
            )
        ),
        parameters: [
            new OA\Parameter(
                name: 'id',
                description: 'Member ID',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'integer')
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Position updated successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(
                            property: 'user',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'email', type: 'string'),
                                new OA\Property(property: 'full_name', type: 'string'),
                                new OA\Property(property: 'position', type: 'string'),
                            ],
                            type: 'object'
                        )
                    ]
                )
            ),
            new OA\Response(
                response: 403,
                description: 'Unauthorized - Admin access required',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: 'User not found',
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
    public function updatePosition(Request $request, int $id): JsonResponse
    {
        if (!Auth::user()->isAdmin()) {
            return response()->json([
                'message' => 'Brak uprawnień. Wymagany dostęp administratora.'
            ], 403);
        }

        $validated = $request->validate([
            'position' => ['required', 'string', 'max:255']
        ]);

        $member = Member::find($id);

        if (!$member) {
            return response()->json([
                'message' => 'Nie znaleziono użytkownika'
            ], 404);
        }

        $member->position = $validated['position'];
        $member->save();

        return response()->json([
            'message' => 'Pozycja użytkownika została pomyślnie zaktualizowana',
            'user' => [
                'id' => $member->id,
                'email' => $member->email,
                'full_name' => $member->full_name,
                'position' => $member->position,
            ]
        ]);
    }

    #[OA\Post(
        path: '/api/member/profile-picture',
        description: 'Upload member profile picture',
        summary: 'Upload or update member profile picture',
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
                        )
                    ]
                )
            )
        ),
        responses: [
            new OA\Response(
                response: 200,
                description: 'Profile picture updated successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(
                            property: 'file',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'url', type: 'string')
                            ],
                            type: 'object'
                        )
                    ]
                )
            )
        ]
    )]
    public function uploadProfilePicture(Request $request): JsonResponse
    {
        $request->validate([
            'file' => 'required|file|image|max:5120'
        ]);

        $file = $request->file('file');
        $fileName = time() . '_profile_' . Auth::id() . '.jpg';

        // Create directory if it doesn't exist
        $directory = storage_path('app/uploads/profile-pictures');
        if (!file_exists($directory)) {
            mkdir($directory, 0755, true);
        }

        // Get source image
        $sourceImage = imagecreatefromstring(file_get_contents($file->getRealPath()));
        $sourceWidth = imagesx($sourceImage);
        $sourceHeight = imagesy($sourceImage);

        // Create a square canvas
        $targetSize = 512;
        $targetImage = imagecreatetruecolor($targetSize, $targetSize);

        // Fill with background color (white) in case of transparent images
        $bgColor = imagecolorallocate($targetImage, 255, 255, 255);
        imagefill($targetImage, 0, 0, $bgColor);

        // Calculate scaling to completely fill the square (may crop)
        $scale = max($targetSize / $sourceWidth, $targetSize / $sourceHeight);
        $newWidth = $sourceWidth * $scale;
        $newHeight = $sourceHeight * $scale;
        $offsetX = ($targetSize - $newWidth) / 2;
        $offsetY = ($targetSize - $newHeight) / 2;

        // Copy resized image onto the new canvas
        imagecopyresampled(
            $targetImage,
            $sourceImage,
            $offsetX,
            $offsetY,
            0,
            0,
            $newWidth,
            $newHeight,
            $sourceWidth,
            $sourceHeight
        );

        // Save as JPEG
        $targetPath = $directory . '/' . $fileName;
        imagejpeg($targetImage, $targetPath, 90);

        // Free memory
        imagedestroy($sourceImage);
        imagedestroy($targetImage);

        $path = 'profile-pictures/' . $fileName;
        $fileSize = filesize($targetPath);

        $fileModel = File::create([
            'original_name' => $file->getClientOriginalName(),
            'file_path' => $path,
            'mime_type' => 'image/jpeg',
            'uploaded_by' => Auth::id(),
            'file_type' => 'image',
            'category' => 'profile',
            'permissions' => 'public',
            'size' => $fileSize
        ]);

        $member = Member::find(Auth::id());
        if ($member) {
            $member->photo = $fileModel->id;
            $member->save();
        }

        return response()->json([
            'message' => 'Profile picture updated successfully',
            'file' => [
                'id' => $fileModel->id,
                'url' => url("api/files/{$fileModel->id}")
            ]
        ]);
    }
    #[OA\Get(
        path: '/api/members/all',
        description: 'List all active and visible members',
        summary: 'Get list of all active and visible members',
        responses: [
            new OA\Response(
                response: 200,
                description: 'Success',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(
                            property: 'members',
                            type: 'array',
                            items: new OA\Items(
                                properties: [
                                    new OA\Property(property: 'id', type: 'integer'),
                                    new OA\Property(property: 'first_name', type: 'string'),
                                    new OA\Property(property: 'last_name', type: 'string'),
                                    new OA\Property(property: 'full_name', type: 'string'),
                                    new OA\Property(property: 'position', type: 'string'),
                                    new OA\Property(property: 'position_translated', type: 'string'),
                                    new OA\Property(property: 'description', type: 'string'),
                                    new OA\Property(property: 'photo_url', type: 'string'),
                                ]
                            )
                        ),
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            )
        ]
    )]
    public function getAllPublicMembers(): JsonResponse
    {
        $members = Member::where('is_active', true)
            ->where('visible', true)
            ->get();

        $response = $members->map(function($member) {
            $photoData = [
                'data' => 'DEFAULT-PROFILE-PICTURE',
                'id' => null
            ];

            if ($member->photo) {
                $file = File::find($member->photo);
                if ($file) {
                    try {
                        $absolutePath = storage_path('app/uploads/profile-pictures/' . basename($file->file_path));

                        if (file_exists($absolutePath)) {
                            $photoData = [
                                'data' => 'data:' . $file->mime_type . ';base64,' . base64_encode(file_get_contents($absolutePath)),
                                'id' => $file->id
                            ];
                        }
                    } catch (\Exception $e) {
                        // Keep default indicator
                    }
                }
            }

            return [
                'id' => $member->id,
                'first_name' => $member->first_name,
                'last_name' => $member->last_name,
                'full_name' => $member->full_name,
                'position' => $member->position,
                'position_translated' => $member->getTranslatedPosition() ?? $member->position,
                'description' => $member->description,
                'photo' => $photoData,
            ];
        });

        return response()->json([
            'members' => $response,
            'message' => 'Pomyślnie zwrócono listę członków'
        ]);
    }


    #[OA\Put(
        path: '/api/member/edit',
        description: 'Edit own profile details',
        summary: 'Update authenticated user profile',
        security: [['sanctum' => []]],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                properties: [
                    new OA\Property(property: 'description', type: 'string'),
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 200,
                description: 'Profile updated successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(
                            property: 'user',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'first_name', type: 'string'),
                                new OA\Property(property: 'last_name', type: 'string'),
                                new OA\Property(property: 'description', type: 'string'),
                            ],
                            type: 'object'
                        )
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
    public function editMember(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'description' => ['sometimes', 'nullable', 'string'],
        ]);

        $member = Auth::user();

        if (isset($validated['description'])) {
            $member->description = $validated['description'];
        }

        $member->save();

        return response()->json([
            'message' => 'Profil został pomyślnie zaktualizowany',
            'user' => [
                'id' => $member->id,
                'first_name' => $member->first_name,
                'last_name' => $member->last_name,
                'description' => $member->description,
            ]
        ]);
    }

    #[OA\Put(
        path: '/api/admin/member/{id}/edit',
        description: 'Edit member profile (Admin only)',
        summary: 'Update profile for a specific user',
        security: [['sanctum' => []]],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                properties: [
                    new OA\Property(property: 'description', type: 'string'),
                ]
            )
        ),
        parameters: [
            new OA\Parameter(
                name: 'id',
                description: 'Member ID',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'integer')
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Profile updated successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(
                            property: 'user',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'full_name', type: 'string'),
                                new OA\Property(property: 'description', type: 'string'),
                            ],
                            type: 'object'
                        )
                    ]
                )
            ),
            new OA\Response(
                response: 403,
                description: 'Unauthorized - Admin access required',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: 'User not found',
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
    public function adminEditMember(Request $request, int $id): JsonResponse
    {
        if (!Auth::user()->isAdmin()) {
            return response()->json([
                'message' => 'Brak uprawnień. Wymagany dostęp administratora.'
            ], 403);
        }

        $validated = $request->validate([
            'description' => ['sometimes', 'nullable', 'string'],
        ]);

        $member = Member::find($id);

        if (!$member) {
            return response()->json([
                'message' => 'Nie znaleziono użytkownika'
            ], 404);
        }

        if (isset($validated['description'])) {
            $member->description = $validated['description'];
        }

        $member->save();

        return response()->json([
            'message' => 'Profil został pomyślnie zaktualizowany',
            'user' => [
                'id' => $member->id,
                'full_name' => $member->full_name,
                'description' => $member->description,
            ]
        ]);
    }

    #[OA\Post(
        path: '/api/member/request-password-reset',
        description: 'Request password reset email',
        summary: 'Request password reset link',
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['email'],
                properties: [
                    new OA\Property(property: 'email', type: 'string', format: 'email')
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 200,
                description: 'Password reset email sent',
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
    public function requestPasswordReset(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => 'required|email|exists:members,email'
        ]);

        $member = Member::where('email', $validated['email'])->first();

        $resetCode = (string) Str::uuid();

        $member->password_reset_code = $resetCode;
        $member->save();

        // TODO: Send password reset email
        // Mail::to($member->email)->send(new PasswordResetMail($member, $resetCode));

        return response()->json([
            'message' => 'Instrukcje resetowania hasła zostały wysłane na Twój adres e-mail'
        ]);
    }

    #[OA\Post(
        path: '/api/member/reset-password',
        description: 'Reset password using reset code',
        summary: 'Reset user password',
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['reset_code', 'password', 'password_confirmation'],
                properties: [
                    new OA\Property(property: 'reset_code', type: 'string'),
                    new OA\Property(property: 'password', type: 'string', format: 'password'),
                    new OA\Property(property: 'password_confirmation', type: 'string', format: 'password')
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 200,
                description: 'Password reset successful',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string')
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: 'Invalid reset code',
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
    public function resetPassword(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'reset_code' => 'required|string|uuid',
            'password' => ['required', 'confirmed', Password::min(8)->mixedCase()->numbers()],
        ]);

        $member = Member::where('password_reset_code', $validated['reset_code'])->first();

        if (!$member) {
            return response()->json([
                'message' => 'Nieprawidłowy kod resetowania hasła'
            ], 404);
        }

        $member->password = Hash::make($validated['password']);
        $member->password_reset_code = null;
        $member->save();

        return response()->json([
            'message' => 'Hasło zostało pomyślnie zresetowane'
        ]);
    }
}
