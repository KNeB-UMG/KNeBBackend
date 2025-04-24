<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Str;
use OpenApi\Attributes as OA;
use Illuminate\Support\Facades\Auth;

#[OA\Info(
    version: '1.0.0',
    title: 'Technical Test API'
)]
class TechnicalController extends Controller
{
    #[OA\Get(
        path: '/api/technical/basic',
        summary: 'basic get endpoint returns test data',
        responses: [
            new OA\Response(
                response: 200,
                description: 'Success',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(property: 'timestamp', type: 'string', format: 'datetime'),
                        new OA\Property(
                            property: 'randomData',
                            properties: [
                                new OA\Property(property: 'number', type: 'integer'),
                                new OA\Property(property: 'string', type: 'string'),
                                new OA\Property(property: 'uuid', type: 'string')
                            ],
                            type: 'object'
                        )
                    ]
                )
            )
        ]
    )]
    public function getBasic(){
        return response()->json([
            'message'=>'basic get response',
            'timestamp'=>now(),
            'randomData'=>[
                'number'=>rand(1,100),
                'string'=>Str::random(10),
                'uuid'=>Str::uuid()
            ]
        ]);
    }

    #[OA\Get(
        path: '/api/technical/auth-test',
        summary: 'Endpoint to test authentication',
        security: [['sanctum' => []]],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Successfully authenticated',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(property: 'user_info', properties: [
                            new OA\Property(property: 'id', type: 'integer'),
                            new OA\Property(property: 'email', type: 'string'),
                            new OA\Property(property: 'role', type: 'string'),
                            new OA\Property(property: 'last_name', type: 'string'),
                            new OA\Property(property: 'full_name', type: 'string')
                        ], type: 'object')
                    ]
                )
            ),
            new OA\Response(
                response: 401,
                description: 'Unauthenticated',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Unauthenticated.')
                    ]
                )
            )
        ]
    )]
    public function testAuth(Request $request) {
        $user = Auth::user();

        return response()->json([
            'message' => 'Authentication successful',
            'user_info' => [
                'id' => $user->id,
                'email' => $user->email,
                'role' => $user->role,
                'last_name' => $user->last_name,
                'full_name' => $user->full_name
            ]
        ]);
    }
}
