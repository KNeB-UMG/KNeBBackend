<?php

namespace App\Http\Controllers;

use App\Models\Member;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use OpenApi\Attributes as OA;
use App\Http\Controllers\Controller;
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
                required: ['email', 'password','firstName','lastName'],
                properties:[
                    new OA\Property(property: 'email' ,type:'string',format:'email'),
                    new OA\Property(property: 'password' ,type:'string',format:'password'),
                    new OA\Property(property: 'first_name' ,type:'string',format:'string'),
                    new OA\Property(property: 'last_name' ,type:'string',format:'string'),
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
    public function registerMember(Request $request): JsonResponse{
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
            'position'=>null,
            'description'=>null,
            'role'=> Member::ROLE_USER,
            'is_active'=>false,
            ]);

        return response()->json([
            'message' => 'User successfully registered',
        ],201);
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
                        )
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
                'message' => 'Account is inactive or has no access'
            ], 403);
        }

        if (!Hash::check($credentials['password'], $member->password)) {
            return response()->json([
                'message' => 'Invalid credentials'
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
            ]
        ]);
    }

}
