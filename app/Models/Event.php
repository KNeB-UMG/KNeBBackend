<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Str;

class Event extends Model
{
    use HasFactory;

    protected $fillable = [
        'title',
        'content',
        'description',
        'event_path',
        'visible',
        'event_date',
        'file_id',
        'author_id',
        'edit_history'
    ];

    protected $casts = [
        'edit_history' => 'array',
        'visible' => 'boolean',
        'event_date' => 'datetime'
    ];

    /**
     * Generate a unique event path from the title
     *
     * @param string $title
     * @return string
     */
    public static function generatePath(string $title): string
    {
        // Convert to lowercase
        $path = Str::lower($title);

        // Replace Polish characters
        $polishChars = ['ą', 'ć', 'ę', 'ł', 'ń', 'ó', 'ś', 'ź', 'ż'];
        $latinChars = ['a', 'c', 'e', 'l', 'n', 'o', 's', 'z', 'z'];
        $path = str_replace($polishChars, $latinChars, $path);

        // Convert to slug (handles spaces, special chars)
        $path = Str::slug($path);

        // Check if path exists and make it unique if needed
        $originalPath = $path;
        $count = 1;

        while (self::where('event_path', $path)->exists()) {
            $path = $originalPath . '-' . $count;
            $count++;
        }

        return $path;
    }

    /**
     * Check if the event can be edited by the given member
     *
     * @param Member $member
     * @return bool
     */
    public function canBeEditedBy(Member $member): bool
    {
        // Admin and moderator can edit any post
        if ($member->isAdmin() || $member->isModerator()) {
            return true;
        }

        // Author can edit their own post if it's not visible yet
        if ($this->author_id === $member->id && !$this->visible) {
            return true;
        }

        return false;
    }

    /**
     * Check if the event can be deleted by the given member
     *
     * @param Member $member
     * @return bool
     */
    public function canBeDeletedBy(Member $member): bool
    {
        // Only admin and moderator can delete posts
        return $member->isAdmin() || $member->isModerator();
    }

    /**
     * Check if the event visibility can be changed by the given member
     *
     * @param Member $member
     * @return bool
     */
    public function visibilityCanBeChangedBy(Member $member): bool
    {
        // Only admin can change visibility
        return $member->isAdmin();
    }

    /**
     * Get the author relationship
     */
    public function author(): BelongsTo
    {
        return $this->belongsTo(Member::class, 'author_id');
    }

    /**
     * Get the file relationship
     */
    public function file(): BelongsTo
    {
        return $this->belongsTo(File::class);
    }
}
