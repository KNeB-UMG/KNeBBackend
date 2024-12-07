<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Laravel\Sanctum\HasApiTokens;

class Member extends Authenticatable
{
    use HasFactory, Notifiable, HasApiTokens;

    public const string ROLE_ADMIN = 'role_admin';
    public const string ROLE_MODERATOR = 'role_moderator';
    public const string ROLE_USER = 'role_user';
    public const string ROLE_NONE = 'role_none';

    private const array ROLE_PERMISSIONS = [
        self::ROLE_ADMIN => [
            'manage_users',
            'manage_roles',
            'manage_content',
            'delete_content',
            'deactivate_users',
            'create_users',
        ],
        self::ROLE_MODERATOR => [
            'manage_content',
            'delete_content',
            'moderate_users'
        ],
        self::ROLE_USER => [
        ],
        self::ROLE_NONE => []
    ];

    protected $fillable = [
        'first_name',
        'last_name',
        'email',
        'password',
        'role',
        'position',
        'deactivation_date',
        'is_active',
        'photo',
        'description'
    ];

    protected $hidden = [
        'password',
    ];

    protected $casts = [
        'is_active' => 'boolean',
        'deactivation_date' => 'datetime'
    ];

    public static function getAvailableRoles(): array
    {
        return [
            self::ROLE_ADMIN,
            self::ROLE_MODERATOR,
            self::ROLE_USER,
            self::ROLE_NONE
        ];
    }
    public function hasRole(string $role): bool
    {
        return $this->role === $role;
    }

    public function isAdmin(): bool
    {
        return $this->hasRole(self::ROLE_ADMIN);
    }

    public function isModerator(): bool
    {
        return $this->hasRole(self::ROLE_MODERATOR);
    }

    public function isActiveUser(): bool
    {
        return $this->is_active && $this->role !== self::ROLE_NONE;
    }

    // Permission-related methods
    public function getPermissions(): array
    {
        return self::ROLE_PERMISSIONS[$this->role] ?? [];
    }

    public function hasPermission(string $permission): bool
    {
        return in_array($permission, $this->getPermissions());
    }

    public function hasAnyPermission(array $permissions): bool
    {
        return !empty(array_intersect($permissions, $this->getPermissions()));
    }

    // Attribute accessors
    protected function fullName(): Attribute
    {
        return Attribute::make(
            get: fn () => "{$this->first_name} {$this->last_name}",
        );
    }

    // Relationships
    public function posts(): HasMany
    {
        return $this->hasMany(Post::class, 'author_id');
    }

    public function events(): HasMany
    {
        return $this->hasMany(Event::class, 'author_id');
    }

    public function uploadedFiles(): HasMany
    {
        return $this->hasMany(File::class, 'uploaded_by');
    }
}
